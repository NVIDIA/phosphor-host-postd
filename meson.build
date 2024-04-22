project(
  'phosphor-host-postd',
  'cpp',
  default_options: [
    'warning_level=3',
    'werror=true',
    'cpp_std=c++23'
  ],
  license: 'Apache-2.0',
  version: '1.0',
  meson_version: '>=1.1.1',
)

build_tests = get_option('tests')

postd_headers = include_directories('.')

phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
sdbusplus = dependency('sdbusplus')
sdeventplus = dependency('sdeventplus')
systemd = dependency('systemd')
phosphor_logging = dependency('phosphor-logging')
libgpiodcxx = dependency('libgpiodcxx')

conf_data = configuration_data()
conf_data.set('bindir', get_option('prefix') / get_option('bindir'))
conf_data.set('SYSTEMD_TARGET', get_option('systemd-target'))
conf_data.set('SYSTEMD_AFTER_SERVICE', get_option('systemd-after-service'))

snoopd_src = ['main.cpp']
snoopd_args = ''
if get_option('snoop').allowed()
  snoopd_src += 'ipmisnoop/ipmisnoop.cpp'
  add_project_arguments('-DENABLE_IPMI_SNOOP',language:'cpp')
  snoopd_args += ' -h "' + get_option('host-instances') + '"'
elif get_option('snoop-device') != ''
  snoopd_args += '-b ' + get_option('post-code-bytes').to_string()
  snoopd_args += ' -d /dev/' + get_option('snoop-device')
  rate_limit = get_option('rate-limit')
  if rate_limit > 0
    snoopd_args += ' --rate-limit=' + rate_limit.to_string()
endif
endif

conf_data.set('SNOOPD_ARGS', snoopd_args)

if  get_option('pcc').enabled()
  add_project_arguments([
       '-DREAD_FROM_PCC',
       ],
      language : 'cpp')
endif

if  get_option('sbmr-boot-progress').enabled()
add_project_arguments([
       '-DREPORT_SBMR',
       ],
      language : 'cpp')
install_data('sbmrbootprogress/sbmr_boot_progress_code.json', install_dir : get_option('datadir') / 'sbmrbootprogress')
endif

configure_file(
  input: 'lpcsnoop.service.in',
  output: 'lpcsnoop.service',
  configuration: conf_data,
  install: true,
  install_dir: systemd.get_variable('systemdsystemunitdir'))

executable(
  'snoopd',
  snoopd_src,
  dependencies: [
    sdbusplus,
    sdeventplus,
    phosphor_dbus_interfaces,
    libgpiodcxx,
  ],
  install: true,
)

executable(
  'snooper',
  'example.cpp',
  dependencies: [
    sdbusplus,
    sdeventplus,
    phosphor_dbus_interfaces,
  ],
  install: true,
)
install_headers(
  'lpcsnoop/snoop.hpp',
  'lpcsnoop/snoop_listen.hpp',
  subdir: 'lpcsnoop')

if not get_option('7seg').disabled()
  udevdir = dependency('udev', required : false).get_variable('udevdir')
  assert(udevdir != '', 'Cannot find udevdir')
  install_data(['80-7seg.rules'], install_dir : udevdir)

  install_data(
    ['postcode-7seg@.service'],
    install_dir: systemd.get_variable('systemdsystemunitdir')
  )

  executable(
    'postcode_7seg',
    '7seg.cpp',
    dependencies: [
      sdbusplus,
      phosphor_dbus_interfaces,
    ],
    install: true,
  )
endif

if not build_tests.disabled()
  subdir('test')
endif
