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
libgpiodcxx = dependency('libgpiodcxx')
libusb = dependency('libusb-1.0')

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

executable('snoopd', snoopd_src, dependencies: deps, install: true)

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
