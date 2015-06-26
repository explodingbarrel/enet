{
  'targets': [
    {
      'target_name': 'enetnative',
      'sources': [ "node/enet.cc","callbacks.cc","compress.cc","host.cc","list.cc","packet.cc","peer.cc","protocol.cc","unix.cc" ],
      'include_dirs': ['include', '<!(node -e "require(\'nan\')")'],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ],
      'conditions': [
        ['OS=="mac"', {
          'xcode_settings': {
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
          }
        }]
      ]
    }
  ]
}