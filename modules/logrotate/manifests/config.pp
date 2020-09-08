# logrotate config
class logrotate::config{

  assert_private()

  $manage_cron_daily = $logrotate::manage_cron_daily
  $logrotate_conf    = $logrotate::logrotate_conf
  $config            = $logrotate::config

  file{ $logrotate::rules_configdir:
    ensure  => directory,
    owner   => $logrotate::root_user,
    group   => $logrotate::root_group,
    purge   => $logrotate::purge_configdir,
    recurse => $logrotate::purge_configdir,
    mode    => $logrotate::rules_configdir_mode,
  }

  $cron_ensure = $manage_cron_daily ? {
    true  => 'present',
    false => 'absent'
  }

  logrotate::cron { 'daily':
    ensure => $cron_ensure,
  }

  if $config {
    logrotate::conf { $logrotate_conf:
      * => $config,
    }
  }

}
