# @api private
#
class secure_linux_cis::distribution::debian9::cis_5_1_1 {
  include secure_linux_cis::rules::ensure_cron_daemon_is_enabled
}