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
                and capabilities.value.features.assignments == 0 },
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
            { 'migration ledger', tonumber(migrations) == 1 }
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
