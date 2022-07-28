executable('sbmr-boot-progress-manager', 
             'sbmr_boot_progress.cpp',
dependencies:
[
  sdbusplus,
  sdeventplus,
  phosphor_logging,
  phosphor_dbus_interfaces,
  ],
 install: true,
 )
  install_data(
    ['SBMR-Boot-Progress.service'],
    install_dir: systemd.get_pkgconfig_variable('systemdsystemunitdir')
  )
  install_data('sbmr_boot_progress_code.json', install_dir : get_option('datadir') / 'sbmrbootprogress')


