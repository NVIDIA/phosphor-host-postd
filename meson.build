project(
    'phosphor-host-postd',
    'cpp',
    default_options: ['warning_level=3', 'werror=true', 'cpp_std=c++23'],
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
# Prefer system libgpiodcxx; fall back to subproject with C++ bindings enabled (for entire-repo coverage).
libgpiodcxx = dependency('libgpiodcxx', required: false)
if not libgpiodcxx.found()
    libgpiod_sp = subproject('libgpiod', default_options: ['bindings=cxx'])
    libgpiodcxx = libgpiod_sp.get_variable('gpiodcxx_dep')
endif
# Prefer system libusb-1.0; fall back to subproject with relaxed flags (libusb 1.0.29 fails under -Werror).
# libusb.h uses C flexible arrays; -Wno-pedantic needed for any C++ that includes it (system or subproject).
libusb_cpp_args = ['-Wno-pedantic']
libusb = dependency('libusb-1.0', required: false)
if not libusb.found()
    libusb_sp = subproject(
        'libusb1',
        default_options: [
            'warning_level=0',
            'werror=false',
            'c_args=-Wno-error -Wno-pedantic',
        ],
    )
    libusb = libusb_sp.get_variable('libusb_dep')
endif

conf_data = configuration_data()
conf_data.set('bindir', get_option('prefix') / get_option('bindir'))
conf_data.set('SYSTEMD_TARGET', get_option('systemd-target'))
conf_data.set('SYSTEMD_AFTER_SERVICE', get_option('systemd-after-service'))

snoopd_src = []
snoopd_args = ''
if get_option('snoop').allowed()
    snoopd_src += 'ipmisnoop/ipmisnoop.cpp'
    add_project_arguments('-DENABLE_IPMI_SNOOP', language: 'cpp')
    snoopd_args += ' -h "' + get_option('host-instances') + '"'
elif get_option('snoop-device') != ''
    snoopd_args += '-b ' + get_option('post-code-bytes').to_string()
    snoopd_args += ' -d /dev/' + get_option('snoop-device')
    rate_limit = get_option('rate-limit')
    if rate_limit > 0
        snoopd_args += ' --rate-limit=' + rate_limit.to_string()
    endif
elif get_option('queued-boot-progress').allowed()
    snoopd_src += 'queued-boot-progress/PollingDevice.cpp'
    snoopd_src += 'queued-boot-progress/I2CPollingDevice.cpp'
    snoopd_src += 'queued-boot-progress/USBPollingDevice.cpp'
    snoopd_src += 'queued-boot-progress/CakBootProgressPublisher.cpp'
    snoopd_src += 'queued-boot-progress/BootProgressPublisher.cpp'
    snoopd_src += 'queued-boot-progress/BootProgressPoller.cpp'
    snoopd_src += 'queued-boot-progress/BootProgressMain.cpp'
    snoopd_src += 'queued-boot-progress/BootProgressManager.cpp'
    snoopd_src += 'queued-boot-progress/dbus_utils.cpp'
    snoopd_src += 'queued-boot-progress/BootProgressApplication.cpp'

    transport = get_option('transport-interface')
    snoopd_args += '-i ' + transport
    if transport == 'i2c'
        buses = get_option('device-bus')
        addrs = get_option('device-address')
        if buses.length() != addrs.length()
            error('device-bus and device-address counts must match')
        endif
        foreach idx : range(buses.length())
            snoopd_args += ' -b ' + buses[idx]
            snoopd_args += ' -a ' + addrs[idx]
        endforeach
    endif
    poll_interval = get_option('poll-interval')
    if poll_interval > 0
        snoopd_args += ' -p ' + poll_interval.to_string()
    endif
    cak_cpu_count = get_option('cak-cpu-count')
    snoopd_args += ' -c ' + cak_cpu_count
    if get_option('cak-boot-progress').allowed()
        snoopd_args += ' -k'
    endif

    snoopd_src += 'queued-boot-progress/L1ResetHandler.cpp'
    if get_option('l1reset').allowed()
        snoopd_args += ' --l1reset'
    endif
endif

if snoopd_src.length() == 0
    snoopd_src += 'main.cpp'
    message('No specific boot progress feature enabled, adding default main.cpp')
endif

conf_data.set('SNOOPD_ARGS', snoopd_args)

if get_option('pcc').enabled()
    add_project_arguments(['-DREAD_FROM_PCC'], language: 'cpp')
endif

if get_option('sbmr-boot-progress').enabled()
    add_project_arguments(['-DREPORT_SBMR'], language: 'cpp')
    install_data(
        'sbmrbootprogress/sbmr_boot_progress_code.json',
        install_dir: get_option('datadir') / 'sbmrbootprogress',
    )
endif

configure_file(
    input: 'lpcsnoop.service.in',
    output: 'lpcsnoop.service',
    configuration: conf_data,
    install: true,
    install_dir: systemd.get_variable('systemdsystemunitdir'),
)

deps = [
    sdbusplus,
    sdeventplus,
    phosphor_dbus_interfaces,
    libgpiodcxx,
    phosphor_logging,
]


if get_option('queued-boot-progress').allowed()
    deps += libusb
endif

executable(
    'snoopd',
    snoopd_src,
    dependencies: deps,
    cpp_args: libusb_cpp_args,
    install: true,
)

executable(
    'snooper',
    'example.cpp',
    dependencies: [sdbusplus, sdeventplus, phosphor_dbus_interfaces],
    install: true,
)

if get_option('7seg').allowed()
    udevdir = dependency('udev', required: false).get_variable('udevdir')
    assert(udevdir != '', 'Cannot find udevdir')
    install_data(['80-7seg.rules'], install_dir: udevdir)

    install_data(
        ['postcode-7seg@.service'],
        install_dir: systemd.get_variable('systemdsystemunitdir'),
    )

    executable(
        'postcode_7seg',
        '7seg.cpp',
        dependencies: [sdbusplus, phosphor_dbus_interfaces],
        install: true,
    )
endif

install_headers(
    'lpcsnoop/snoop.hpp',
    'lpcsnoop/snoop_listen.hpp',
    subdir: 'lpcsnoop',
)

if build_tests.allowed()
    subdir('test')
endif

# gcovr-based coverage targets (use gcovr.cfg for exclusions)
if get_option('b_coverage')
    _src = meson.project_source_root()
    _bld = meson.project_build_root()
    _coveragedir = join_paths(_bld, 'meson-logs', 'coveragereport')
    run_command('mkdir', '-p', _coveragedir, check: false)
    _gcovr_cfg = join_paths(_src, 'gcovr.cfg')
    _coverage_html_cmd = [
        find_program('gcovr'),
        '-r',
        _src,
        '--config',
        _gcovr_cfg,
        '--html',
        '--html-details',
        '-o',
        join_paths(_coveragedir, 'index.html'),
    ]
    run_target('coverage-gcovr', command: _coverage_html_cmd)
    run_target('coverage-html-gcovr', command: _coverage_html_cmd)
    run_target(
        'coverage-txt',
        command: [
            find_program('gcovr'),
            '-r',
            _src,
            '--config',
            _gcovr_cfg,
            '--txt',
            '-o',
            join_paths(_coveragedir, 'coverage.txt'),
        ],
    )
    run_target(
        'coverage-validate',
        command: [find_program('ninja'), '-C', _bld, 'test', 'coverage-gcovr'],
    )
endif
