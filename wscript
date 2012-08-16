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

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.target = "enet"
  obj.source = ["node/enet.cc","callbacks.cc","compress.cc","host.cc","list.cc","packet.cc","peer.cc","protocol.cc","unix.cc"]
  obj.includes = '. .. include'
  obj.defines = ['HAS_POLL','HAS_FCNTL','HAS_SOCKLEN_T','HAS_INET_NTOP','HAS_INET_PTON']
  # obj.uselib = "NODE"

def shutdown():
  try:
  	unlink('enet.node')
  except:
  	print('')
  	
  if exists('build/Release/enet.node') and not exists('enet.node'): symlink('build/Release/enet.node', 'enet.node')
  if exists('build/default/enet.node') and not exists('enet.node'): symlink('build/default/enet.node', 'enet.node')