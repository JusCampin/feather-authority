AuthorityMigrations = {}
local definitions = {
    {
        id = '001_capability_registry',
        statements = {
            [[CREATE TABLE IF NOT EXISTS `feather_authority_capabilities` (
                `capability_id` CHAR(36) NOT NULL,
                `capability_key` VARCHAR(100) NOT NULL,
                `description` VARCHAR(255) NOT NULL,
                `risk_class` VARCHAR(16) NOT NULL,
                `owner_resource` VARCHAR(100) NOT NULL,
                `status` VARCHAR(16) NOT NULL DEFAULT 'active',
                `revision` BIGINT UNSIGNED NOT NULL DEFAULT 1,
                `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `retired_at` TIMESTAMP NULL,
                PRIMARY KEY (`capability_id`),
                UNIQUE KEY `uq_authority_capability_key` (`capability_key`),
                CONSTRAINT `chk_authority_capability_risk`
                    CHECK (`risk_class` IN ('low','moderate','high','critical')),
                CONSTRAINT `chk_authority_capability_status`
                    CHECK (`status` IN ('active','retired'))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin]]
        }
    }
}

local function Hash(value)
    local hash = 2166136261
    for index = 1, #value do hash = ((hash ~ value:byte(index)) * 16777619) & 0xffffffff end
    return ('fnv1a32:%08x'):format(hash)
end

function AuthorityMigrations.Run()
    MySQL.query.await([[CREATE TABLE IF NOT EXISTS `feather_authority_schema_migrations` (
        `id` VARCHAR(100) NOT NULL,
        `checksum` VARCHAR(64) NOT NULL,
        `applied_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin]])
    local count = 0
    for _, migration in ipairs(definitions) do
        local checksum = Hash(table.concat(migration.statements, '\n-- next statement --\n'))
        local applied = MySQL.single.await(
            'SELECT `checksum` FROM `feather_authority_schema_migrations` WHERE `id`=?', { migration.id })
        if applied and applied.checksum ~= checksum then
            return Authority.Err('migration_checksum_mismatch', 'An applied Authority migration changed.', {
                migrationId = migration.id
            })
        end
        if not applied then
            for _, statement in ipairs(migration.statements) do MySQL.query.await(statement) end
            MySQL.insert.await(
                'INSERT INTO `feather_authority_schema_migrations` (`id`,`checksum`) VALUES (?,?)',
                { migration.id, checksum })
            count = count + 1
        end
    end
    return Authority.Ok({ total = #definitions, applied = count })
end
