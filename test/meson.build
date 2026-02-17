
gtest = dependency('gtest', disabler: true, required: build_tests)
gtest_main = dependency('gtest_main', disabler: true, required: build_tests)
gmock = dependency('gmock', disabler: true, required: build_tests)
phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
sdbusplus = dependency('sdbusplus')

tests = ['post_reporter_test', 'sbmr_boot_progress_test']

foreach t : tests
    test(
        t,
        executable(
            t.underscorify(),
            t + '.cpp',
            include_directories: postd_headers,
            implicit_include_directories: false,
            dependencies: [
                gtest,
                gtest_main,
                gmock,
                phosphor_dbus_interfaces,
                sdbusplus,
                phosphor_logging,
            ],
        ),
    )
endforeach

test(
    'test_snoop_listen',
    executable(
        'test_snoop_listen',
        'test_snoop_listen.cpp',
        include_directories: postd_headers,
        implicit_include_directories: false,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
        ],
    ),
)

test(
    'test_boot_progress_types',
    executable(
        'test_boot_progress_types',
        'test_boot_progress_types.cpp',
        include_directories: postd_headers,
        implicit_include_directories: false,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
        ],
    ),
)

test(
    'test_config_reader',
    executable(
        'test_config_reader',
        'test_config_reader.cpp',
        include_directories: postd_headers,
        implicit_include_directories: false,
        cpp_args: libusb_cpp_args,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
            libusb,
        ],
    ),
)

test(
    'test_polling_device',
    executable(
        'test_polling_device',
        'test_polling_device.cpp',
        include_directories: postd_headers,
        implicit_include_directories: false,
        cpp_args: libusb_cpp_args,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
            libusb,
        ],
    ),
)

test(
    'test_boot_progress_poller',
    executable(
        'test_boot_progress_poller',
        'test_boot_progress_poller.cpp',
        '../queued-boot-progress/BootProgressPoller.cpp',
        include_directories: [postd_headers, include_directories('.')],
        implicit_include_directories: false,
        cpp_args: libusb_cpp_args,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
            libusb,
        ],
    ),
)

test(
    'test_polling_device_enumerator',
    executable(
        'test_polling_device_enumerator',
        'test_polling_device_enumerator.cpp',
        'polling_device_factory.cpp',
        '../queued-boot-progress/I2CPollingDevice.cpp',
        '../queued-boot-progress/PollingDevice.cpp',
        '../queued-boot-progress/USBPollingDevice.cpp',
        '../queued-boot-progress/BootProgressManager.cpp',
        '../queued-boot-progress/CakBootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPoller.cpp',
        include_directories: [postd_headers, include_directories('.')],
        implicit_include_directories: false,
        cpp_args: libusb_cpp_args,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
            libusb,
        ],
    ),
)

test(
    'test_usb_polling_device',
    executable(
        'test_usb_polling_device',
        'test_usb_polling_device.cpp',
        'polling_device_factory.cpp',
        '../queued-boot-progress/I2CPollingDevice.cpp',
        '../queued-boot-progress/PollingDevice.cpp',
        '../queued-boot-progress/USBPollingDevice.cpp',
        '../queued-boot-progress/BootProgressManager.cpp',
        '../queued-boot-progress/CakBootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPoller.cpp',
        include_directories: [postd_headers, include_directories('.')],
        implicit_include_directories: false,
        cpp_args: libusb_cpp_args,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
            libusb,
        ],
    ),
)

test(
    'test_initialize_i2c_devices',
    executable(
        'test_initialize_i2c_devices',
        'test_initialize_i2c_devices.cpp',
        '../queued-boot-progress/I2CPollingDevice.cpp',
        '../queued-boot-progress/PollingDevice.cpp',
        '../queued-boot-progress/USBPollingDevice.cpp',
        '../queued-boot-progress/BootProgressManager.cpp',
        '../queued-boot-progress/CakBootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPoller.cpp',
        include_directories: postd_headers,
        implicit_include_directories: false,
        cpp_args: libusb_cpp_args,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
            libusb,
        ],
    ),
)

test(
    'test_boot_progress_manager',
    executable(
        'test_boot_progress_manager',
        'test_boot_progress_manager.cpp',
        'mock_device_factory.cpp',
        '../queued-boot-progress/BootProgressManager.cpp',
        '../queued-boot-progress/CakBootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPoller.cpp',
        include_directories: [postd_headers, include_directories('.')],
        implicit_include_directories: false,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
        ],
    ),
    timeout: 45,
)

test(
    'test_boot_progress_application',
    executable(
        'test_boot_progress_application',
        'test_boot_progress_application.cpp',
        'stub_polling_device_factory.cpp',
        '../queued-boot-progress/dbus_utils.cpp',
        '../queued-boot-progress/BootProgressApplication.cpp',
        '../queued-boot-progress/BootProgressManager.cpp',
        '../queued-boot-progress/CakBootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPoller.cpp',
        include_directories: [postd_headers, include_directories('.')],
        implicit_include_directories: false,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
        ],
    ),
    timeout: 120,
)

test(
    'test_boot_progress_publisher',
    executable(
        'test_boot_progress_publisher',
        'test_boot_progress_publisher.cpp',
        '../queued-boot-progress/CakBootProgressPublisher.cpp',
        '../queued-boot-progress/BootProgressPublisher.cpp',
        include_directories: postd_headers,
        implicit_include_directories: false,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
        ],
    ),
)

test(
    'test_cak_boot_progress_publisher',
    executable(
        'test_cak_boot_progress_publisher',
        'test_cak_boot_progress_publisher.cpp',
        '../queued-boot-progress/CakBootProgressPublisher.cpp',
        include_directories: postd_headers,
        implicit_include_directories: false,
        dependencies: [
            gtest,
            gtest_main,
            gmock,
            phosphor_dbus_interfaces,
            sdbusplus,
            phosphor_logging,
        ],
    ),
)

if 'address' in get_option('b_sanitize')
    add_test_setup(
        'valgrind',
        exclude_suites: [meson.project_name()],
        timeout_multiplier: 10,
    )
else
    add_test_setup(
        'valgrind',
        exe_wrapper: ['valgrind', '--error-exitcode=1'],
        timeout_multiplier: 10,
    )
endif

