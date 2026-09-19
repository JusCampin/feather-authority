AuthorityCapabilities = {}
local catalog = {}

function AuthorityCapabilities.Load()
    for _, definition in ipairs(Config.Capabilities) do
        local existing = MySQL.single.await(
            'SELECT `owner_resource` FROM `feather_authority_capabilities` WHERE `capability_key`=?',
            { definition.key })
        if existing and existing.owner_resource ~= GetCurrentResourceName() then
            return Authority.Err('capability_owner_conflict', 'Configured capability belongs to another resource.', {
                capabilityKey = definition.key
            })
        end
        MySQL.query.await([[INSERT INTO `feather_authority_capabilities`
            (`capability_id`,`capability_key`,`description`,`risk_class`,`owner_resource`)
            VALUES (UUID(),?,?,?,?) ON DUPLICATE KEY UPDATE
                `revision`=`revision` + IF(`description`<>VALUES(`description`)
                    OR `risk_class`<>VALUES(`risk_class`),1,0),
                `description`=VALUES(`description`),
                `risk_class`=VALUES(`risk_class`)]], {
            definition.key, definition.description, definition.riskClass, GetCurrentResourceName()
        })
    end
    local rows = MySQL.query.await([[SELECT `capability_id`,`capability_key`,`description`,
        `risk_class`,`owner_resource`,`status`,`revision`
        FROM `feather_authority_capabilities` ORDER BY `capability_key` LIMIT 129]]) or {}
    if #rows > 128 then
        return Authority.Err('capability_catalog_limit', 'Capability catalog exceeds the foundation limit of 128.')
    end
    local loaded = {}
    for _, row in ipairs(rows) do
        local revision = tonumber(row.revision)
        if not Authority.Uuid(row.capability_id) or not Authority.Integer(revision, 1, 9007199254740991)
            or (row.status ~= 'active' and row.status ~= 'retired') then
            return Authority.Err('invalid_persistence', 'Persisted capability identity, status, or revision is invalid.')
        end
        loaded[row.capability_key] = {
            capabilityId = row.capability_id,
            key = row.capability_key,
            description = row.description,
            riskClass = row.risk_class,
            ownerResource = row.owner_resource,
            status = row.status,
            revision = revision
        }
    end
    catalog = loaded
    return Authority.Ok({ capabilities = #rows })
end

function AuthorityCapabilities.Get(key, resource)
    local allowed = Authority.CheckRead(resource)
    if not allowed.ok then return allowed end
    if type(key) ~= 'string' or #key > 100
        or not key:match('^[a-z][a-z0-9_]*%.[a-z][a-z0-9_.]*$')
        or key:find('..', 1, true) then
        return Authority.Err('invalid_input', 'Valid capability key required.')
    end
    if not catalog[key] then return Authority.Err('capability_not_found', 'Capability was not found.') end
    return Authority.Ok(Authority.Copy(catalog[key]))
end

function AuthorityCapabilities.List(resource)
    local allowed = Authority.CheckRead(resource)
    if not allowed.ok then return allowed end
    local result = {}
    for _, definition in pairs(catalog) do result[#result + 1] = Authority.Copy(definition) end
    table.sort(result, function(left, right) return left.key < right.key end)
    return Authority.Ok(result)
end

exports('GetCapability', function(key)
    return AuthorityCapabilities.Get(key, GetInvokingResource())
end)
exports('ListCapabilities', function()
    return AuthorityCapabilities.List(GetInvokingResource())
end)
