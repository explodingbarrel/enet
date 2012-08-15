import Options
from os import unlink, symlink, popen
from os.path import exists 

srcdir = "."
blddir = "build"
VERSION = "0.1.0"

def set_options(opt):
  opt.tool_options("compiler_cxx")
  opt.add_option( '--debug'
                , action='store_true'
                , default=False
                , help='Build debug variant [Default: False]'
                , dest='debug'
                )  

def configure(conf):
  conf.check_tool("compiler_cxx")
  conf.check_tool("node_addon")
  conf.env.append_value('CXXFLAGS', ['-O3', '-funroll-loops'])

  # conf.env.append_value('CXXFLAGS', ['-DDEBUG', '-g', '-O0', '-Wall', '-Wextra'])
  # conf.check(lib='node', libpath=['/usr/lib', '/usr/local/lib'], uselib_store='NODE')

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.target = "enet"
  obj.source = ["node/enet.cc","callbacks.cc","compress.cc","host.cc","list.cc","packet.cc","peer.cc","protocol.cc","unix.cc"]
  obj.includes = '. .. include'
  # obj.uselib = "NODE"

def shutdown():
  # HACK to get compress.node out of build directory.
  # better way to do this?
  try:
  	unlink('bson.node')
  except:
  	print('')
  	
  if exists('build/Release/enet.node') and not exists('enet.node'): symlink('build/Release/enet.node', 'enet.node')
  if exists('build/default/enet.node') and not exists('enet.node'): symlink('build/default/enet.node', 'enet.node')