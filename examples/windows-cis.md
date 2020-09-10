# Windows CIS Examples

```
# CIS 1.1.4
# (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' (Scored)

dsc_accountpolicy { 'MinimumPasswordLength' :
  dsc_name  => 'Minimum_Password_Length',
  dsc_minimum_password_length  => '14',
}


# CIS 1.1.5
# (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Scored)

dsc_accountpolicy { 'PasswordComplexity' :
    dsc_name  => 'Password_must_meet_complexity_requirements',
    dsc_password_must_meet_complexity_requirements  => 'Enabled',
  }
```