CreateThread(function()
    local called, result = xpcall(function()
        local valid = Authority.ValidateConfig()
        if not valid.ok then return valid end
        Authority.SetState('waiting', 'waiting_for_dependencies')
        local core = exports['feather-core']:AwaitReady(Config.ReadinessTimeoutMs)
        if type(core) ~= 'table' or not core.ok then
            return Authority.Err('dependency_unavailable', 'Core did not become ready.')
        end
        local coreCapabilities = exports['feather-core']:GetCapabilities()
        if type(coreCapabilities) ~= 'table' or not coreCapabilities.ok
            or type(coreCapabilities.value) ~= 'table'
            or coreCapabilities.value.contract ~= Config.RequiredCoreContract then
            return Authority.Err('dependency_unavailable', 'Core Contract 1 is required.')
        end
        local organizations = exports['feather-organizations']:AwaitReady(Config.ReadinessTimeoutMs)
        if type(organizations) ~= 'table' or not organizations.ok then
            return Authority.Err('dependency_unavailable', 'Organizations did not become ready.')
        end
        local organizationCapabilities = exports['feather-organizations']:GetCapabilities()
        if type(organizationCapabilities) ~= 'table' or not organizationCapabilities.ok
            or type(organizationCapabilities.value) ~= 'table'
            or organizationCapabilities.value.contract ~= Config.RequiredOrganizationsContract then
            return Authority.Err('dependency_unavailable', 'Organizations Contract 1 is required.')
        end
        Authority.SetState('migrating', 'database_migrations')
        local migrated = AuthorityMigrations.Run()
        if not migrated.ok then return migrated end
        Authority.SetState('starting', 'loading_capabilities')
        local loaded = AuthorityCapabilities.Load()
        if not loaded.ok then return loaded end
        Authority.SetState('ready', 'ready')
        print(('[feather-authority] event=startup.ready migrationsApplied=%d capabilities=%d'):format(
            migrated.value.applied, loaded.value.capabilities))
        return Authority.Ok(true)
    end, debug.traceback)
    if not called then
        print('[feather-authority] startup traceback: ' .. tostring(result))
        Authority.Fail(Authority.Err('startup_failed', 'Authority startup raised an exception.'))
    elseif not result.ok then Authority.Fail(result) end
end)

AddEventHandler('onResourceStop', function(resource)
    if resource == 'feather-core' or resource == 'feather-organizations' or resource == 'oxmysql' then
        Authority.Fail(Authority.Err('dependency_unavailable',
            'A required dependency stopped. Restart Authority after it is ready.'))
    elseif resource == GetCurrentResourceName() then
        Authority.SetState('stopped', 'resource_stopped')
    end
end)

Authority.RegisterDevCommand('AuthorityFoundationSmokeTest', function(source)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        local owner = GetCurrentResourceName()
        local capabilities = Authority.GetCapabilities()
        local health = Authority.GetHealth()
        local listed = AuthorityCapabilities.List(owner)
        local staff = AuthorityCapabilities.Get('staff.authority.manage', owner)
        local roleplay = AuthorityCapabilities.Get('rp.organization.treasury.approve', owner)
        local snapshot = staff.ok and staff.value or {}
        snapshot.description = 'mutated'
        local fresh = AuthorityCapabilities.Get('staff.authority.manage', owner)
        local denied = AuthorityCapabilities.List('untrusted-smoke-caller')
        local unknown = AuthorityCapabilities.Get('staff.unknown.test', owner)
        local invalid = AuthorityCapabilities.Get({}, owner)
        local persisted = MySQL.single.await([[SELECT `capability_id` FROM
            `feather_authority_capabilities` WHERE `capability_key`=?]], { 'staff.authority.manage' })
        local migrations = MySQL.scalar.await('SELECT COUNT(*) FROM `feather_authority_schema_migrations`')
        local function Valid(result, key, namespace)
            return result.ok and result.value.key == key and Authority.Uuid(result.value.capabilityId)
                and result.value.status == 'active' and result.value.revision >= 1
                and result.value.key:sub(1, #namespace + 1) == namespace .. '.'
        end
        local tests = {
            { 'capabilities', capabilities.ok and capabilities.value.contract == 1
                and capabilities.value.features.capabilityRegistry == 1
                and capabilities.value.features.assignments == 1 },
            { 'health ready', health.ok and health.value.state == 'ready' },
            { 'bounded catalog', listed.ok and #listed.value == #Config.Capabilities and #listed.value <= 128 },
            { 'staff namespace', Valid(staff, 'staff.authority.manage', 'staff') },
            { 'roleplay namespace', Valid(roleplay, 'rp.organization.treasury.approve', 'rp') },
            { 'snapshot isolated', fresh.ok and fresh.value.description ~= 'mutated' },
            { 'untrusted rejected', not denied.ok and denied.code == 'authorization_denied' },
            { 'unknown rejected', not unknown.ok and unknown.code == 'capability_not_found' },
            { 'invalid rejected', not invalid.ok and invalid.code == 'invalid_input' },
            { 'await ready', Authority.AwaitReady(0).ok },
            { 'persisted identity', staff.ok and persisted
                and persisted.capability_id == staff.value.capabilityId },
            { 'migration ledger', tonumber(migrations) == 6 }
        }
        local passed = 0
        for _, test in ipairs(tests) do
            if test[2] then passed = passed + 1 end
            print(('[AuthorityFoundationSmokeTest] %-21s %s'):format(test[1], test[2] and 'PASS' or 'FAIL'))
        end
        print(('[AuthorityFoundationSmokeTest] done %d/%d passed (read-only)'):format(passed, #tests))
    end, debug.traceback)
    if not called then print('[AuthorityFoundationSmokeTest] FAIL ' .. tostring(reason)) end
end, true)

Authority.RegisterDevCommand('AuthorityAssignmentContractSmokeTest', function(source)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        local valid = { requestId = 'authority-assignment-contract-001', subjectType = 'account',
            subjectId = '00000000-0000-4000-8000-000000000001',
            roleId = '00000000-0000-4000-8000-000000000002', expectedRoleRevision = 2,
            scopeType = 'server', validUntil = 1893456000, reason = 'Contract acceptance',
            reasonCode = 'development.contract' }
        local first = AuthorityAssignments.ValidateIssue(valid)
        local same = AuthorityAssignments.ValidateIssue(Authority.Copy(valid))
        local changed = Authority.Copy(valid); changed.reason = 'Changed reason'
        local changedResult = AuthorityAssignments.ValidateIssue(changed)
        local function Rejected(field, value)
            local request = Authority.Copy(valid); request[field] = value
            return not AuthorityAssignments.ValidateIssue(request).ok
        end
        local injected = Authority.Copy(valid); injected.assignmentId = valid.subjectId
        local untrusted = AuthorityAssignments.Issue(valid, 'untrusted-smoke-caller')
        local tests = {
            { 'assignment contract', Authority.GetCapabilities().value.features.assignmentContracts == 1
                and Authority.GetCapabilities().value.features.assignments == 1 },
            { 'valid account assignment', first.ok },
            { 'untrusted rejected', not untrusted.ok and untrusted.code == 'authorization_denied' },
            { 'stable fingerprint', same.ok and same.value == first.value },
            { 'payload binding', changedResult.ok and changedResult.value ~= first.value },
            { 'character subject rejected', Rejected('subjectType', 'character') },
            { 'bad subject rejected', Rejected('subjectId', 'not-a-uuid') },
            { 'bad role rejected', Rejected('roleId', 'not-a-uuid') },
            { 'zero revision rejected', Rejected('expectedRoleRevision', 0) },
            { 'unknown scope rejected', Rejected('scopeType', 'organization') },
            { 'fractional expiry rejected', Rejected('validUntil', 1.5) },
            { 'blank reason rejected', Rejected('reason', '   ') },
            { 'identity injection rejected', not AuthorityAssignments.ValidateIssue(injected).ok }
        }
        local passed = 0
        for _, test in ipairs(tests) do
            if test[2] then passed = passed + 1 end
            print(('[AuthorityAssignmentContractSmokeTest] %-27s %s'):format(
                test[1], test[2] and 'PASS' or 'FAIL'))
        end
        print(('[AuthorityAssignmentContractSmokeTest] done %d/%d passed (no assignments created)'):format(
            passed, #tests))
    end, debug.traceback)
    if not called then print('[AuthorityAssignmentContractSmokeTest] FAIL ' .. tostring(reason)) end
end, true)

Authority.RegisterDevCommand('AuthorityAssignmentLiveTest', function(source, args)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        assert(type(args) == 'table' and #args == 3 and tonumber(args[1])
            and Authority.Uuid(args[2]) and type(args[3]) == 'string',
            'Use <player source> <role UUID> <stable requestId>')
        local account = exports['feather-core']:GetAccountContext(tonumber(args[1]))
        assert(account.ok, 'Active Core account context required for the acceptance test')
        local role = AuthorityRoles.Get({ roleId = args[2] }, GetCurrentResourceName())
        assert(role.ok, tostring(role.code) .. ': ' .. tostring(role.message))
        local request = { requestId = args[3], subjectType = 'account',
            subjectId = account.value.accountId, roleId = role.value.roleId,
            expectedRoleRevision = role.value.revision, scopeType = 'server',
            reason = 'Authority assignment live acceptance', reasonCode = 'development.live_test' }
        local first = AuthorityAssignments.Issue(request, GetCurrentResourceName())
        assert(first.ok, tostring(first.code) .. ': ' .. tostring(first.message))
        local replay = AuthorityAssignments.Issue(request, GetCurrentResourceName())
        assert(replay.ok and replay.value.replayed and replay.value.assignmentId == first.value.assignmentId,
            'Exact assignment did not replay its identity')
        local mismatch = Authority.Copy(request); mismatch.reason = 'Changed reason'
        local mismatchResult = AuthorityAssignments.Issue(mismatch, GetCurrentResourceName())
        assert(not mismatchResult.ok and mismatchResult.code == 'idempotency_conflict',
            'Changed assignment payload did not conflict')
        local stale = Authority.Copy(request); stale.requestId = args[3] .. ':stale'
        stale.expectedRoleRevision = math.max(1, role.value.revision - 1)
        local staleResult = AuthorityAssignments.Issue(stale, GetCurrentResourceName())
        assert(not staleResult.ok and (role.value.revision == 1
            and staleResult.code == 'assignment_conflict' or staleResult.code == 'revision_conflict'),
            'Stale role revision was accepted')
        local read = AuthorityAssignments.Get({ assignmentId = first.value.assignmentId }, GetCurrentResourceName())
        assert(read.ok and read.value.subjectId == account.value.accountId
            and read.value.issuerId == GetCurrentResourceName(), 'Assignment attribution is invalid')
        local assignmentCount = tonumber(MySQL.scalar.await([[SELECT COUNT(*) FROM
            `feather_authority_assignments` WHERE `assignment_id`=?]], { first.value.assignmentId }))
        local eventCount = tonumber(MySQL.scalar.await([[SELECT COUNT(*) FROM
            `feather_authority_assignment_events` WHERE `assignment_id`=?]], { first.value.assignmentId }))
        assert(assignmentCount == 1 and eventCount == 1,
            'Assignment did not produce exactly one identity and audit event')
        print(('[AuthorityAssignmentLiveTest] PASS assignment=%s account=%s role=%s firstReplayed=%s replayed=true mismatchRejected=true staleRejected=true attribution=true singleAssignmentAudit=true'):format(
            first.value.assignmentId, account.value.accountId, role.value.roleId,
            tostring(first.value.replayed)))
    end, debug.traceback)
    if not called then print('[AuthorityAssignmentLiveTest] FAIL ' .. tostring(reason)) end
end, true)

Authority.RegisterDevCommand('AuthorityAssignmentOfflineReplayTest', function(source, args)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        assert(type(args) == 'table' and #args == 3 and Authority.Uuid(args[1])
            and Authority.Uuid(args[2]) and type(args[3]) == 'string',
            'Use <account UUID> <role UUID> <original requestId>')
        local role = AuthorityRoles.Get({ roleId = args[2] }, GetCurrentResourceName())
        assert(role.ok, tostring(role.code) .. ': ' .. tostring(role.message))
        local request = { requestId = args[3], subjectType = 'account', subjectId = args[1],
            roleId = args[2], expectedRoleRevision = role.value.revision, scopeType = 'server',
            reason = 'Authority assignment live acceptance', reasonCode = 'development.live_test' }
        local replay = AuthorityAssignments.Issue(request, GetCurrentResourceName())
        assert(replay.ok and replay.value.replayed == true,
            tostring(replay.code) .. ': original assignment did not replay')
        local identity = exports['feather-core']:GetAccountIdentity(args[1])
        local read = AuthorityAssignments.Get({ assignmentId = replay.value.assignmentId },
            GetCurrentResourceName())
        local events = tonumber(MySQL.scalar.await([[SELECT COUNT(*) FROM
            `feather_authority_assignment_events` WHERE `assignment_id`=?]],
            { replay.value.assignmentId }))
        assert(identity.ok and read.ok and read.value.subjectId == identity.value.accountId
            and events == 1, 'Offline assignment identity or audit evidence changed')
        print(('[AuthorityAssignmentOfflineReplayTest] PASS assignment=%s account=%s role=%s replayed=true activeSessionNotRequired=true singleAssignmentAudit=true'):format(
            replay.value.assignmentId, identity.value.accountId, role.value.roleId))
    end, debug.traceback)
    if not called then print('[AuthorityAssignmentOfflineReplayTest] FAIL ' .. tostring(reason)) end
end, true)

Authority.RegisterDevCommand('AuthorityEvaluationContractSmokeTest', function(source)
    if source ~= 0 then return end
    local base = { subjectType = 'account', subjectId = '00000000-0000-4000-8000-000000000001',
        capabilityKey = 'staff.players.view', scopeType = 'server' }
    local function Rejected(field, value)
        local request = Authority.Copy(base); request[field] = value
        return not AuthorityEvaluation.Validate(request).ok
    end
    local injected = Authority.Copy(base); injected.source = 1
    local denied = AuthorityEvaluation.Evaluate(base, 'untrusted-smoke-caller')
    local unknown = Authority.Copy(base); unknown.capabilityKey = 'staff.unknown.contract'
    local unknownResult = AuthorityEvaluation.Evaluate(unknown, GetCurrentResourceName())
    local tests = {
        { 'evaluation capability', Authority.GetCapabilities().value.features.scopedEvaluation == 1 },
        { 'valid request', AuthorityEvaluation.Validate(base).ok },
        { 'untrusted rejected', not denied.ok and denied.code == 'authorization_denied' },
        { 'character rejected', Rejected('subjectType', 'character') },
        { 'bad subject rejected', Rejected('subjectId', 'not-a-uuid') },
        { 'bad capability rejected', Rejected('capabilityKey', 'staff..view') },
        { 'unknown scope rejected', Rejected('scopeType', 'organization') },
        { 'identity injection rejected', not AuthorityEvaluation.Validate(injected).ok },
        { 'unknown capability denied', unknownResult.ok and not unknownResult.value.allowed
            and unknownResult.value.reason == 'capability_unavailable' },
        { 'policy version returned', unknownResult.ok
            and Authority.Integer(unknownResult.value.policyVersion, 1, 9007199254740991) }
    }
    local passed = 0
    for _, test in ipairs(tests) do
        if test[2] then passed = passed + 1 end
        print(('[AuthorityEvaluationContractSmokeTest] %-27s %s'):format(
            test[1], test[2] and 'PASS' or 'FAIL'))
    end
    print(('[AuthorityEvaluationContractSmokeTest] done %d/%d passed (read-only)'):format(passed, #tests))
end, true)

Authority.RegisterDevCommand('AuthorityEvaluationLiveTest', function(source, args)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        assert(type(args) == 'table' and #args == 1 and Authority.Uuid(args[1]),
            'Use <account UUID>')
        local allow = AuthorityEvaluation.Evaluate({ subjectType = 'account', subjectId = args[1],
            capabilityKey = 'staff.players.view', scopeType = 'server' }, GetCurrentResourceName())
        local deny = AuthorityEvaluation.Evaluate({ subjectType = 'account', subjectId = args[1],
            capabilityKey = 'staff.economy.adjust', scopeType = 'server' }, GetCurrentResourceName())
        assert(allow.ok and allow.value.allowed and allow.value.reason == 'explicit_role_grant'
            and Authority.Uuid(allow.value.assignmentId) and Authority.Uuid(allow.value.roleId)
            and Authority.Uuid(allow.value.grantId), 'Expected explicit role grant allow')
        assert(deny.ok and not deny.value.allowed and deny.value.reason == 'no_active_assignment',
            'Ungrantable capability did not deny')
        assert(allow.value.policyVersion == deny.value.policyVersion,
            'Read-only decisions observed inconsistent policy versions')
        print(('[AuthorityEvaluationLiveTest] PASS account=%s allowed=true reason=%s denied=true denyReason=%s policyVersion=%d attribution=true activeSessionNotRequired=true'):format(
            args[1], allow.value.reason, deny.value.reason, allow.value.policyVersion))
    end, debug.traceback)
    if not called then print('[AuthorityEvaluationLiveTest] FAIL ' .. tostring(reason)) end
end, true)

Authority.RegisterDevCommand('AuthorityRoleGrantContractSmokeTest', function(source)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        local valid = {
            requestId = 'authority-grant-contract-001',
            roleId = '00000000-0000-4000-8000-000000000001',
            capabilityKey = 'staff.players.view',
            expectedRevision = 1,
            scopeType = 'server',
            reasonCode = 'development.contract'
        }
        local first = AuthorityGrants.ValidateIssue(valid)
        local same = AuthorityGrants.ValidateIssue(Authority.Copy(valid))
        local changed = Authority.Copy(valid)
        changed.scopeType = 'organization'
        local changedFingerprint = AuthorityGrants.ValidateIssue(changed)
        local function Rejected(field, value)
            local request = Authority.Copy(valid)
            request[field] = value
            return not AuthorityGrants.ValidateIssue(request).ok
        end
        local injected = Authority.Copy(valid)
        injected.effect = 'deny'
        local tests = {
            { 'grant contract capability', Authority.GetCapabilities().value.features.roleGrantContracts == 1
                and Authority.GetCapabilities().value.features.roleGrants == 1 },
            { 'valid request', first.ok },
            { 'stable fingerprint', same.ok and same.value == first.value },
            { 'payload binding', changedFingerprint.ok and changedFingerprint.value ~= first.value },
            { 'deny injection rejected', not AuthorityGrants.ValidateIssue(injected).ok },
            { 'untrusted rejected', (function()
                local result = AuthorityGrants.Issue(valid, 'untrusted-smoke-caller')
                return not result.ok and result.code == 'authorization_denied'
            end)() },
            { 'bad role rejected', Rejected('roleId', 'not-a-uuid') },
            { 'bad capability rejected', Rejected('capabilityKey', 'staff..view') },
            { 'zero revision rejected', Rejected('expectedRevision', 0) },
            { 'fractional revision rejected', Rejected('expectedRevision', 1.5) },
            { 'string revision rejected', Rejected('expectedRevision', '1') },
            { 'unknown scope rejected', Rejected('scopeType', 'global') },
            { 'identity injection rejected', (function()
                local request = Authority.Copy(valid)
                request.grantId = '00000000-0000-4000-8000-000000000002'
                return not AuthorityGrants.ValidateIssue(request).ok
            end)() }
        }
        local passed = 0
        for _, test in ipairs(tests) do
            if test[2] then passed = passed + 1 end
            print(('[AuthorityRoleGrantContractSmokeTest] %-28s %s'):format(
                test[1], test[2] and 'PASS' or 'FAIL'))
        end
        print(('[AuthorityRoleGrantContractSmokeTest] done %d/%d passed (no grants created)'):format(
            passed, #tests))
    end, debug.traceback)
    if not called then print('[AuthorityRoleGrantContractSmokeTest] FAIL ' .. tostring(reason)) end
end, true)

Authority.RegisterDevCommand('AuthorityRoleContractSmokeTest', function(source)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        local valid = {
            requestId = 'authority-role-contract-001',
            roleKey = 'staff.server_operator',
            label = 'Server Operator',
            roleClass = 'staff',
            reasonCode = 'development.contract'
        }
        local first = AuthorityRoles.ValidateCreate(valid)
        local same = AuthorityRoles.ValidateCreate(Authority.Copy(valid))
        local changed = Authority.Copy(valid)
        changed.label = 'Changed Label'
        local changedFingerprint = AuthorityRoles.ValidateCreate(changed)
        local denied = AuthorityRoles.Create(valid, 'untrusted-smoke-caller')
        local tests = {
            { 'role capability', Authority.GetCapabilities().value.features.roles == 1 },
            { 'valid staff role', first.ok },
            { 'stable fingerprint', same.ok and same.value == first.value },
            { 'payload binding', changedFingerprint.ok and changedFingerprint.value ~= first.value },
            { 'untrusted rejected', not denied.ok and denied.code == 'authorization_denied' },
            { 'class mismatch rejected', not AuthorityRoles.ValidateCreate({
                requestId = valid.requestId, roleKey = 'rp.server_operator', label = valid.label,
                roleClass = 'staff', reasonCode = valid.reasonCode
            }).ok },
            { 'unknown class rejected', not AuthorityRoles.ValidateCreate({
                requestId = valid.requestId, roleKey = valid.roleKey, label = valid.label,
                roleClass = 'system', reasonCode = valid.reasonCode
            }).ok },
            { 'identity injection rejected', not AuthorityRoles.ValidateCreate({
                requestId = valid.requestId, roleKey = valid.roleKey, label = valid.label,
                roleClass = valid.roleClass, reasonCode = valid.reasonCode,
                roleId = '00000000-0000-4000-8000-000000000001'
            }).ok },
            { 'status injection rejected', not AuthorityRoles.ValidateCreate({
                requestId = valid.requestId, roleKey = valid.roleKey, label = valid.label,
                roleClass = valid.roleClass, reasonCode = valid.reasonCode, status = 'active'
            }).ok },
            { 'control label rejected', not AuthorityRoles.ValidateCreate({
                requestId = valid.requestId, roleKey = valid.roleKey, label = 'Bad\nLabel',
                roleClass = valid.roleClass, reasonCode = valid.reasonCode
            }).ok },
            { 'missing request rejected', not AuthorityRoles.ValidateCreate({
                roleKey = valid.roleKey, label = valid.label,
                roleClass = valid.roleClass, reasonCode = valid.reasonCode
            }).ok },
            { 'malformed key rejected', not AuthorityRoles.ValidateCreate({
                requestId = valid.requestId, roleKey = 'staff..operator', label = valid.label,
                roleClass = valid.roleClass, reasonCode = valid.reasonCode
            }).ok }
        }
        local passed = 0
        for _, test in ipairs(tests) do
            if test[2] then passed = passed + 1 end
            print(('[AuthorityRoleContractSmokeTest] %-28s %s'):format(test[1], test[2] and 'PASS' or 'FAIL'))
        end
        print(('[AuthorityRoleContractSmokeTest] done %d/%d passed (no roles created)'):format(passed, #tests))
    end, debug.traceback)
    if not called then print('[AuthorityRoleContractSmokeTest] FAIL ' .. tostring(reason)) end
end, true)

Authority.RegisterDevCommand('AuthorityRoleLiveTest', function(source, args)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        assert(type(args) == 'table' and #args == 1 and type(args[1]) == 'string'
            and #args[1] >= 1 and #args[1] <= 80
            and args[1]:match('^[A-Za-z0-9][A-Za-z0-9._:%-]*$'),
            'Use <stable requestId>')
        local requestId = args[1]
        local slug = requestId:lower():gsub('[^a-z0-9_]', '_')
        assert(#slug <= 70, 'Request ID is too long for the acceptance role key')
        local roleKey = 'staff.acceptance_' .. slug
        local request = {
            requestId = requestId,
            roleKey = roleKey,
            label = 'Authority Acceptance Operator',
            roleClass = 'staff',
            reasonCode = 'development.live_test'
        }
        local first = AuthorityRoles.Create(request, GetCurrentResourceName())
        assert(first.ok, tostring(first.code) .. ': ' .. tostring(first.message))
        local replay = AuthorityRoles.Create(request, GetCurrentResourceName())
        assert(replay.ok and replay.value.replayed == true, 'Exact role creation did not replay')
        assert(replay.value.roleId == first.value.roleId, 'Replay changed role identity')
        local mismatch = Authority.Copy(request)
        mismatch.label = 'Tampered Acceptance Operator'
        local mismatchResult = AuthorityRoles.Create(mismatch, GetCurrentResourceName())
        assert(not mismatchResult.ok and mismatchResult.code == 'idempotency_conflict',
            'Changed payload did not conflict with the request receipt')
        local keyConflict = Authority.Copy(request)
        keyConflict.requestId = requestId .. ':key-conflict'
        local keyConflictResult = AuthorityRoles.Create(keyConflict, GetCurrentResourceName())
        assert(not keyConflictResult.ok and keyConflictResult.code == 'role_key_conflict',
            'Duplicate role key was not rejected')
        local byId = AuthorityRoles.Get({ roleId = first.value.roleId }, GetCurrentResourceName())
        local byKey = AuthorityRoles.Find({ roleKey = roleKey }, GetCurrentResourceName())
        assert(byId.ok and byKey.ok and byId.value.roleId == byKey.value.roleId,
            'Role identity reads are inconsistent')
        byId.value.label = 'mutated'
        local fresh = AuthorityRoles.Get({ roleId = first.value.roleId }, GetCurrentResourceName())
        assert(fresh.ok and fresh.value.label == request.label, 'Role snapshot was not isolated')
        local roleCount = tonumber(MySQL.scalar.await(
            'SELECT COUNT(*) FROM `feather_authority_roles` WHERE `role_key`=?', { roleKey }))
        local eventCount = tonumber(MySQL.scalar.await([[SELECT COUNT(*) FROM
            `feather_authority_role_events` WHERE `role_id`=? AND `event_type`='authority.role.created']],
            { first.value.roleId }))
        local receiptCount = tonumber(MySQL.scalar.await([[SELECT COUNT(*) FROM
            `feather_authority_role_creation_receipts` WHERE `source_resource`=? AND `request_id`=?]],
            { GetCurrentResourceName(), requestId }))
        assert(roleCount == 1 and eventCount == 1 and receiptCount == 1,
            'Role creation did not produce exactly one identity, event, and receipt')
        print(('[AuthorityRoleLiveTest] PASS id=%s key=%s firstReplayed=%s replayed=true mismatchRejected=true keyConflict=true singleRoleAudit=true'):format(
            first.value.roleId, roleKey, tostring(first.value.replayed)))
    end, debug.traceback)
    if not called then print('[AuthorityRoleLiveTest] FAIL ' .. tostring(reason)) end
end, true)

Authority.RegisterDevCommand('AuthorityRoleGrantLiveTest', function(source, args)
    if source ~= 0 then return end
    local called, reason = xpcall(function()
        assert(type(args) == 'table' and #args == 2 and type(args[1]) == 'string'
            and Authority.Uuid(args[2]), 'Use <stable requestId> <role UUID>')
        local role = AuthorityRoles.Get({ roleId = args[2] }, GetCurrentResourceName())
        assert(role.ok, tostring(role.code) .. ': ' .. tostring(role.message))
        local prior = MySQL.single.await([[SELECT `revision` FROM `feather_authority_role_events`
            WHERE `role_id`=? AND `source_resource`=? AND `request_id`=?
                AND `event_type`='authority.role.grant_added']],
            { role.value.roleId, GetCurrentResourceName(), args[1] })
        local expectedRevision = prior and tonumber(prior.revision) - 1 or role.value.revision
        local request = { requestId = args[1], roleId = role.value.roleId,
            capabilityKey = 'staff.players.view', expectedRevision = expectedRevision,
            scopeType = 'server', reasonCode = 'development.live_test' }
        local first = AuthorityGrants.Issue(request, GetCurrentResourceName())
        assert(first.ok, tostring(first.code) .. ': ' .. tostring(first.message))
        local replay = AuthorityGrants.Issue(request, GetCurrentResourceName())
        assert(replay.ok and replay.value.replayed and replay.value.grantId == first.value.grantId,
            'Exact grant did not replay its identity')
        local mismatch = Authority.Copy(request); mismatch.scopeType = 'organization'
        local mismatchResult = AuthorityGrants.Issue(mismatch, GetCurrentResourceName())
        assert(not mismatchResult.ok and mismatchResult.code == 'idempotency_conflict',
            'Changed grant payload did not conflict')
        local stale = Authority.Copy(request); stale.requestId = args[1] .. ':stale'
        stale.capabilityKey = 'staff.economy.adjust'
        local staleResult = AuthorityGrants.Issue(stale, GetCurrentResourceName())
        assert(not staleResult.ok and staleResult.code == 'revision_conflict', 'Stale role revision was accepted')
        local classMismatch = Authority.Copy(request); classMismatch.requestId = args[1] .. ':class'
        classMismatch.capabilityKey = 'rp.organization.treasury.approve'
        classMismatch.expectedRevision = first.value.roleRevision
        local classResult = AuthorityGrants.Issue(classMismatch, GetCurrentResourceName())
        assert(not classResult.ok and classResult.code == 'class_mismatch', 'Cross-class grant was accepted')
        local grants = tonumber(MySQL.scalar.await([[SELECT COUNT(*) FROM `feather_authority_role_grants`
            WHERE `role_id`=? AND `status`='active']], { role.value.roleId }))
        local events = tonumber(MySQL.scalar.await([[SELECT COUNT(*) FROM `feather_authority_role_events`
            WHERE `role_id`=? AND `event_type`='authority.role.grant_added']], { role.value.roleId }))
        assert(grants == 1 and events == 1, 'Grant did not produce exactly one active grant and audit event')
        print(('[AuthorityRoleGrantLiveTest] PASS role=%s grant=%s revision=%d firstReplayed=%s replayed=true mismatchRejected=true staleRejected=true classMismatch=true singleGrantAudit=true'):format(
            role.value.roleId, first.value.grantId, first.value.roleRevision, tostring(first.value.replayed)))
    end, debug.traceback)
    if not called then print('[AuthorityRoleGrantLiveTest] FAIL ' .. tostring(reason)) end
end, true)
