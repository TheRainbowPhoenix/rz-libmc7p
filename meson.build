project('libmc7', 'c',
  version: 'v0.5.0',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ])


libmc7_deps = []
libmc7_incs = ['.', 'src','include']

if get_option('build_shared_libs')
  rizin = find_program('rizin', required: false)
  rz_core_dep = dependency('rz_core')
  libmc7_deps += rz_core_dep
  libmc7_deps += dependency('rz_util')
  libmc7_deps += dependency('rz_cons')
  libmc7_deps += dependency('rz_config')
  libmc7_deps += dependency('rz_io')

  rizin_plugdir = ''
  if rizin_plugdir == ''
    rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
    plugin_libmc7_dir = join_paths(get_option('prefix'), rizin_plugdir, 'libmc7')
  else
    plugin_libmc7_dir = join_paths(rizin_plugdir, 'libmc7')
  endif

  libmc7_c_args = []
  libmc7_asm_src = [
    'src' / 'simatic.c',
    'src' / 'plugin_arch.c',
  ]
  shared_library('libmc7_arch', libmc7_asm_src,
    c_args : libmc7_c_args,
    dependencies: libmc7_deps,
    include_directories: include_directories(libmc7_incs),
    implicit_include_directories: false,
    install: true,
    install_dir: rizin_plugdir
  )
  libmc7_bin_src = [
    'src' / 'simatic.c',
    'src' / 'plugin_bin.c',
  ]
  shared_library('libmc7_bin', libmc7_bin_src,
    c_args : libmc7_c_args,
    dependencies: libmc7_deps,
    include_directories: include_directories(libmc7_incs),
    implicit_include_directories: false,
    install: true,
    install_dir: rizin_plugdir
  )
  # MC7+ (S7-1200/1500) arch plugin -- separate plugin, both MC7 dialects
  # stay available (asm.arch=mc7 / asm.arch=mc7plus).  Plugin file is named
  # rz_libmc7p (.so/.dll); rizin loads it via the fixed `rizin_plugin` symbol.
  libmc7plus_asm_src = [
    'src' / 'mc7plus_isa.c',
    'src' / 'mc7plus.c',
    'src' / 'mc7plus_asm.c',
    'src' / 'plugin_arch_mc7plus.c',
  ]
  shared_library('rz_libmc7p', libmc7plus_asm_src,
    c_args : libmc7_c_args,
    dependencies: libmc7_deps,
    include_directories: include_directories(libmc7_incs),
    implicit_include_directories: false,
    install: true,
    install_dir: rizin_plugdir,
    name_prefix: '',
  )
endif

libmc7_src = ['src' / 'simatic.c']

exe = executable('test_simatic', ['unit' / 'test_simatic.c'] + libmc7_src,
  c_args: [],
  include_directories: include_directories(libmc7_incs),
  dependencies: [],
  install: false,
  implicit_include_directories: false)

test('test_simatic', exe)

# --------------------------------------------------------------- MC7+ port
# standalone decoder + assembler-text renderer (zymatik-reference port);
# no rizin dependency, built and tested on every CI run
libmc7plus_src = [
  'src' / 'mc7plus_isa.c',
  'src' / 'mc7plus.c',
  'src' / 'mc7plus_asm.c',
]

dis_mc7plus = executable('dis_mc7plus', ['unit' / 'dis_mc7plus.c'] + libmc7plus_src,
  c_args: [],
  include_directories: include_directories(libmc7_incs),
  dependencies: [],
  install: false,
  implicit_include_directories: false)

test_mc7plus = executable('test_mc7plus', ['unit' / 'test_mc7plus.c'] + libmc7plus_src,
  c_args: [],
  include_directories: include_directories(libmc7_incs),
  dependencies: [],
  install: false,
  implicit_include_directories: false)

test('test_mc7plus', test_mc7plus)

test_mc7plus_asm_roundtrip = executable('test_mc7plus_asm_roundtrip',
  ['unit' / 'test_mc7plus_asm_roundtrip.c'] + libmc7plus_src,
  c_args: [],
  include_directories: include_directories(libmc7_incs),
  dependencies: [],
  install: false,
  implicit_include_directories: false)

test('test_mc7plus_asm_roundtrip', test_mc7plus_asm_roundtrip)
