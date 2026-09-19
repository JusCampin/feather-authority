AuthorityAssignments = {}
local Ok, Err = Authority.Ok, Authority.Err

local function Token(value, maximum, lower)
    if type(value) ~= 'string' or #value < 1 or #value > maximum then return false end
    return value:match(lower and '^[a-z][a-z0-9._:%-]*$'
        or '^[A-Za-z0-9][A-Za-z0-9._:%-]*$') ~= nil
end
local function Text(value, maximum)
    return type(value) == 'string' and #value > 0 and #value <= maximum
        and not value:find('%c') and value:find('%S') ~= nil
end

function AuthorityAssignments.ValidateIssue(request)
    if type(request) ~= 'table' then return Err('invalid_input', 'Assignment request required.') end
    local fields = { requestId = true, subjectType = true, subjectId = true, roleId = true,
        expectedRoleRevision = true, scopeType = true, validUntil = true, reason = true,
        reasonCode = true }
    for field in pairs(request) do
        if not fields[field] then return Err('invalid_input', 'Unexpected assignment field.') end
    end
    if not Token(request.requestId, 128, false) or request.subjectType ~= 'account'
        or not Authority.Uuid(request.subjectId) or not Authority.Uuid(request.roleId)
        or not Authority.Integer(request.expectedRoleRevision, 1, 9007199254740991)
        or request.scopeType ~= 'server' or not Text(request.reason, 255)
        or not Token(request.reasonCode, 64, true)
        or (request.validUntil ~= nil and not Authority.Integer(request.validUntil, 1, 4102444800)) then
        return Err('invalid_input', 'Account, role revision, server scope, expiry, reason, and stable IDs are required.')
    end
    local fingerprint = {}
    for _, field in ipairs({ 'subjectType', 'subjectId', 'roleId', 'expectedRoleRevision',
        'scopeType', 'validUntil', 'reason', 'reasonCode' }) do
        local value = request[field] == nil and '' or tostring(request[field])
        fingerprint[#fingerprint + 1] = tostring(#value) .. ':' .. value
    end
    return Ok(table.concat(fingerprint))
end

local function Snapshot(row)
    if not row then return Err('assignment_not_found', 'Authority assignment was not found.') end
    local revision = tonumber(row.revision)
    if not Authority.Uuid(row.assignment_id) or row.subject_type ~= 'account'
        or not Authority.Uuid(row.subject_id) or not Authority.Uuid(row.role_id)
        or row.issuer_type ~= 'service_principal' or type(row.issuer_id) ~= 'string'
        or row.scope_type ~= 'server'
        or (row.status ~= 'active' and row.status ~= 'suspended' and row.status ~= 'revoked')
        or not Authority.Integer(revision, 1, 9007199254740991) then
        return Err('invalid_persistence', 'Persisted Authority assignment is invalid.')
    end
    return Ok({ assignmentId = row.assignment_id, subjectType = row.subject_type,
        subjectId = row.subject_id, roleId = row.role_id, issuerType = row.issuer_type,
        issuerId = row.issuer_id, scopeType = row.scope_type, validFrom = row.valid_from,
        validUntil = row.valid_until, status = row.status, reason = row.reason, revision = revision })
end

function AuthorityAssignments.Get(request, resource)
    local allowed = Authority.CheckRead(resource)
    if not allowed.ok then return allowed end
    if type(request) ~= 'table' or not Authority.Uuid(request.assignmentId) then
        return Err('invalid_input', 'Assignment UUID required.')
    end
    for field in pairs(request) do
        if field ~= 'assignmentId' then return Err('invalid_input', 'Unexpected assignment read field.') end
    end
    return Snapshot(MySQL.single.await(
        'SELECT * FROM `feather_authority_assignments` WHERE `assignment_id`=?',
        { request.assignmentId:lower() }))
end

function AuthorityAssignments.Issue(request, resource)
    if Config.Access.trustedAssigners[resource or ''] ~= true then
        return Err('authorization_denied', 'Calling resource is not a trusted assigner.')
    end
    local allowed = Authority.CheckRead(resource)
    if not allowed.ok then return allowed end
    local valid = AuthorityAssignments.ValidateIssue(request)
    if not valid.ok then return valid end
    local identity = exports['feather-core']:GetAccountIdentity(request.subjectId)
    if type(identity) ~= 'table' or not identity.ok or type(identity.value) ~= 'table'
        or identity.value.accountId:lower() ~= request.subjectId:lower() then
        return Err('subject_not_found', 'Canonical account subject was not found.')
    end
    if identity.value.status ~= 'active' then return Err('subject_inactive', 'Account subject is not active.') end
    request = Authority.Copy(request)
    local result
    local called, committed = pcall(MySQL.startTransaction, function(query)
        local executed, outcome = xpcall(function()
            query([[INSERT IGNORE INTO `feather_authority_assignment_receipts`
                (`source_resource`,`request_id`,`request_fingerprint`) VALUES (?,?,?)]],
                { resource, request.requestId, valid.value })
            local receipts = query([[SELECT `request_fingerprint`,`result_json` FROM
                `feather_authority_assignment_receipts` WHERE `source_resource`=? AND `request_id`=? FOR UPDATE]],
                { resource, request.requestId }) or {}
            local receipt = receipts[1]
            if not receipt then return Err('internal_error', 'Assignment receipt could not be reserved.') end
            if receipt.request_fingerprint ~= valid.value then
                return Err('idempotency_conflict', 'Request ID is bound to a different assignment payload.')
            end
            if receipt.result_json then
                local decoded, value = pcall(json.decode, receipt.result_json)
                if not decoded or type(value) ~= 'table' or not Authority.Uuid(value.assignmentId) then
                    return Err('invalid_persistence', 'Stored assignment receipt is invalid.')
                end
                value.replayed = true
                return Ok(value)
            end
            local roles = query('SELECT * FROM `feather_authority_roles` WHERE `role_id`=? FOR UPDATE',
                { request.roleId:lower() }) or {}
            local role = roles[1]
            if not role then return Err('role_not_found', 'Authority role was not found.') end
            if role.status ~= 'active' then return Err('role_inactive', 'Authority role is not active.') end
            if role.role_class ~= 'staff' then return Err('class_mismatch', 'Account assignments require a staff role.') end
            if tonumber(role.revision) ~= request.expectedRoleRevision then
                return Err('revision_conflict', 'Authority role revision changed.')
            end
            local existing = query([[SELECT `assignment_id` FROM `feather_authority_assignments`
                WHERE `subject_type`='account' AND `subject_id`=? AND `role_id`=?
                    AND `scope_type`='server' AND `status` IN ('active','suspended') FOR UPDATE]],
                { request.subjectId:lower(), request.roleId:lower() }) or {}
            if existing[1] then return Err('assignment_conflict', 'An active assignment already exists.') end
            local ids = query('SELECT UUID() AS `assignment_id`,UUID() AS `event_id`') or {}
            local assignmentId, eventId = ids[1] and ids[1].assignment_id, ids[1] and ids[1].event_id
            if not Authority.Uuid(assignmentId) or not Authority.Uuid(eventId) then
                return Err('internal_error', 'Could not generate assignment identities.')
            end
            query([[INSERT INTO `feather_authority_assignments`
                (`assignment_id`,`subject_type`,`subject_id`,`role_id`,`issuer_type`,`issuer_id`,
                    `scope_type`,`valid_until`,`reason`) VALUES (?,'account',?,?,'service_principal',?,
                    'server',FROM_UNIXTIME(?),?)]],
                { assignmentId, request.subjectId:lower(), request.roleId:lower(), resource,
                    request.validUntil, request.reason })
            local rows = query('SELECT * FROM `feather_authority_assignments` WHERE `assignment_id`=? FOR UPDATE',
                { assignmentId }) or {}
            local created = Snapshot(rows[1])
            if not created.ok then return created end
            created.value.roleRevision = request.expectedRoleRevision
            created.value.replayed = false
            query([[INSERT INTO `feather_authority_assignment_events`
                (`event_id`,`assignment_id`,`event_type`,`source_resource`,`request_id`,`reason_code`,`revision`)
                VALUES (?,?,'authority.assignment.issued',?,?,?,1)]],
                { eventId, assignmentId, resource, request.requestId, request.reasonCode })
            query([[UPDATE `feather_authority_assignment_receipts` SET `result_json`=?
                WHERE `source_resource`=? AND `request_id`=?]],
                { json.encode(created.value), resource, request.requestId })
            query('UPDATE `feather_authority_policy_state` SET `policy_version`=`policy_version`+1 WHERE `id`=1')
            return created
        end, debug.traceback)
        if not executed then result = Err('internal_error', 'Assignment transaction failed.'); return false end
        result = outcome
        return outcome.ok == true
    end)
    if not called or (result and result.ok and committed ~= true) then
        return Err('transaction_failed', 'Assignment did not confirm commit. Retry the same request ID.')
    end
    return result or Err('transaction_failed', 'Assignment did not complete. Retry the same request ID.')
end

exports('IssueAssignment', function(request)
    local called, result = xpcall(function()
        return AuthorityAssignments.Issue(request, GetInvokingResource())
    end, debug.traceback)
    if not called then return Err('internal_error', 'Authority assignment operation failed.') end
    return result
end)
exports('GetAssignment', function(request)
    return AuthorityAssignments.Get(request, GetInvokingResource())
end)
