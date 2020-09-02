Param(
  $action,
  $feature
)

switch ($action) {
  'uninstall' { $cmd = Uninstall-WindowsFeature $feature }
  'install'   { $cmd = Install-WindowsFeature $feature -IncludeManagementTools }
}

$cmd
