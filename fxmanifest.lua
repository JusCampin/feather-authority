fx_version 'cerulean'
game 'rdr3'
rdr3_warning 'I acknowledge that this is a prerelease build of RedM, and I am aware my resources *will* become incompatible once RedM ships.'
lua54 'yes'

name 'feather-authority'
author 'Feather Framework'
description 'Durable capability and assignment authority for the Feather Framework'
version '0.1.0'

server_scripts {
    '@oxmysql/lib/MySQL.lua',
    'config.lua',
    'server/foundation.lua',
    'server/migrations.lua',
    'server/capabilities.lua',
    'server/roles.lua',
    'server/grants.lua',
    'server/assignments.lua',
    'server/evaluation.lua',
    'server/main.lua'
}

dependencies { 'oxmysql', 'feather-core', 'feather-organizations' }
