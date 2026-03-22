#!/usr/bin/env bash
###############################################################################
#
# Bash Remediation Script generated from evaluation of DISA STIG for Red Hat Enterprise Linux 9

###############################################################################
# Define CHROOT variable - set to empty string for non-chroot environment
# or set to the chroot path (e.g., /mnt/rootfs) for chroot environment
CHROOT="${CHROOT:-}"
#set -x
# Function to get the correct path with or without chroot prefix
get_path() {
    local path="$1"
    if [ -n "$CHROOT" ]; then
        echo "${CHROOT}${path}"
    else
        echo "$path"
    fi
}

###############################################################################
# BEGIN fix  for 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'"); (

var_system_crypto_policy='FIPS'

# In chroot environment, we need to modify the file directly
CRYPTO_POLICY_FILE=$(get_path "/etc/crypto-policies/config")
if [ -f "$CRYPTO_POLICY_FILE" ]; then
    echo "$var_system_crypto_policy" > "$CRYPTO_POLICY_FILE"
else
    mkdir -p "$(dirname "$CRYPTO_POLICY_FILE")"
    echo "$var_system_crypto_policy" > "$CRYPTO_POLICY_FILE"
fi
CRYPTO_STATE_FILE=$(get_path "/etc/crypto-policies/state/current")
if [ -f "$CRYPTO_STATE_FILE" ]; then
    echo "$var_system_crypto_policy" > "$CRYPTO_STATE_FILE"
else
    mkdir -p "$(dirname "$CRYPTO_STATE_FILE")"
    echo "$var_system_crypto_policy" > "$CRYPTO_STATE_FILE"
fi

# Update symbolic links in back-ends directory to point to FIPS
CRYPTO_POLICIES_DIR=$(get_path "/usr/share/crypto-policies")
CRYPTO_POLICIES_BACKENDS=$(get_path "/etc/crypto-policies/back-ends")

# Ensure the back-ends directory exists
mkdir -p "$CRYPTO_POLICIES_BACKENDS"

# Find all .config files in the back-ends directory and update their symlinks
if [ -d "$CRYPTO_POLICIES_BACKENDS" ]; then
    # First check if there are any existing config files
    if ls "$CRYPTO_POLICIES_BACKENDS"/*.config >/dev/null 2>&1; then
        for config_file in "$CRYPTO_POLICIES_BACKENDS"/*.config; do
            if [ -L "$config_file" ]; then
                base_name=$(basename "$config_file")
                target_file="/usr/share/crypto-policies/$var_system_crypto_policy/${base_name%.config}.txt"
                if [ -f "$target_file" ]; then
                    rm -f "$config_file"
                    ln -sf "/usr/share/crypto-policies/$var_system_crypto_policy/${base_name%.config}.txt" "$config_file"
                fi
            fi
        done
    else
        # If no config files exist, create them based on available txt files in FIPS directory
        if [ -d "$(get_path "$CRYPTO_POLICIES_DIR/$var_system_crypto_policy")" ]; then
            for txt_file in $(get_path "$CRYPTO_POLICIES_DIR/$var_system_crypto_policy")/*.txt; do
                if [ -f "$txt_file" ]; then
                    base_name=$(basename "$txt_file")
                    config_name="${base_name%.txt}.config"
                    ln -sf "/usr/share/crypto-policies/$var_system_crypto_policy/$base_name" "$CRYPTO_POLICIES_BACKENDS/$config_name"
                fi
            done
        fi
    fi
fi

(>&2 echo "Crypto policy set to $var_system_crypto_policy in chroot environment")

) # END fix for 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_openssh_conf_crypto_policy'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_openssh_conf_crypto_policy'"); (

# In chroot environment, modify files directly
OPENSSH_CONF="$(get_path "/etc/ssh/ssh_config")"

# Check if the file exists
if [ -f "$OPENSSH_CONF" ]; then
    # Comment out any existing Ciphers lines
    sed -i 's/^\s*Ciphers/#Ciphers/' "$OPENSSH_CONF"

    # Add the new Ciphers line at the end of the file
    if ! grep -q "^Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$OPENSSH_CONF"; then
        echo "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> "$OPENSSH_CONF"
    fi
else
    echo "Error: $OPENSSH_CONF does not exist" >&2

fi


) # END fix for 'xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_openssh_conf_crypto_policy'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_opensshserver_conf_crypto_policy'
###############################################################################
(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_opensshserver_conf_crypto_policy'"); (

# In chroot environment, modify files directly
SSHD_CONF="$(get_path "/etc/ssh/sshd_config")"

# Check if the file exists
if [ -f "$SSHD_CONF" ]; then
    # Comment out any existing Ciphers lines
    sed -i 's/^\s*Ciphers/#Ciphers/' "$SSHD_CONF"

    # Add the new Ciphers line at the end of the file
    if ! grep -q "^Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$SSHD_CONF"; then
        echo "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> "$SSHD_CONF"
    fi
else
    echo "Error: $SSHD_CONF does not exist" >&2

fi

) # END fix for 'xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_opensshserver_conf_crypto_policy'

###############################################################################
# BEGIN fix  for 'xccdf_org.ssgproject.content_rule_harden_sshd_macs_openssh_conf_crypto_policy'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_harden_sshd_macs_openssh_conf_crypto_policy'"); (

# In chroot environment, modify files directly
OPENSSH_CONF="$(get_path "/etc/ssh/ssh_config")"

# Check if the file exists
if [ -f "$OPENSSH_CONF" ]; then
    # Comment out any existing MACs lines
    sed -i 's/^\s*MACs/#MACs/' "$OPENSSH_CONF"

    # Add the new MACs line at the end of the file
    if ! grep -q "^MACs hmac-sha2-512,hmac-sha2-256" "$OPENSSH_CONF"; then
        echo "MACs hmac-sha2-512,hmac-sha2-256" >> "$OPENSSH_CONF"
    fi
else
    echo "Error: $OPENSSH_CONF does not exist" >&2

fi


) # END fix for 'xccdf_org.ssgproject.content_rule_harden_sshd_macs_openssh_conf_crypto_policy'

###############################################################################
# BEGIN fix  for 'xccdf_org.ssgproject.content_rule_harden_sshd_macs_opensshserver_conf_crypto_policy'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_harden_sshd_macs_opensshserver_conf_crypto_policy'"); (

# In chroot environment, modify files directly
SSHD_CONF="$(get_path "/etc/ssh/sshd_config")"

# Check if the file exists
if [ -f "$SSHD_CONF" ]; then
    # Comment out any existing MACs lines
    sed -i 's/^\s*MACs/#MACs/' "$SSHD_CONF"

    # Add the new MACs line at the end of the file
    if ! grep -q "^MACs hmac-sha2-512,hmac-sha2-256" "$SSHD_CONF"; then
        echo "MACs hmac-sha2-512,hmac-sha2-256" >> "$SSHD_CONF"
    fi
else
    echo "Error: $SSHD_CONF does not exist" >&2

fi

) # END fix for 'xccdf_org.ssgproject.content_rule_harden_sshd_macs_opensshserver_conf_crypto_policy'


###############################################################################
# BEGIN fix  for 'xccdf_org.ssgproject.content_rule_enable_authselect'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_enable_authselect'"); (

var_authselect_profile='sssd'

if [ -n "$CHROOT" ]; then
    # In chroot environment, we can't run authselect commands
    (>&2 echo "Skipping authselect in chroot environment")

    # PROFILE_DIR=/usr/share/authselect/default/${var_authselect_profile}

    # # Check if already configured (equivalent to authselect current succeeding)
    # if [ -f "${CHROOT}/etc/authselect/authselect.conf" ]; then
    #     echo "Authselect is already configured. No changes needed."
    #     exit 0
    # fi

    # # Backup existing files if they exist and are not already authselect symlinks (mimics --force)
    # for file in /etc/nsswitch.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/fingerprint-auth /etc/pam.d/smartcard-auth /etc/pam.d/postlogin; do
    #     full_path="${CHROOT}${file}"
    #     target_link="/etc/authselect${file#/etc/pam.d}"
    #     if [ -f "${full_path}" ] && ( [ ! -L "${full_path}" ] || [ "$(readlink "${full_path}")" != "${target_link}" ] ); then
    #         mv "${full_path}" "${full_path}.authselect.bak"
    #         echo "Backed up ${file} to ${file}.authselect.bak"
    #     fi
    # done

    # # Create authselect directory
    # mkdir -p "${CHROOT}/etc/authselect"

    # # Copy profile files (these are the templates; authselect would generate from them, but for plain sssd, direct copy works)
    # cp -p "${CHROOT}${PROFILE_DIR}"/* "${CHROOT}/etc/authselect/" || { echo "Failed to copy profile files from ${PROFILE_DIR}"; exit 1; }

    # # Create authselect.conf
    # echo "default/${var_authselect_profile}" > "${CHROOT}/etc/authselect/authselect.conf"

    # # Set symlinks
    # ln -sf /etc/authselect/nsswitch.conf "${CHROOT}/etc/nsswitch.conf"
    # for pam_file in system-auth password-auth fingerprint-auth smartcard-auth postlogin; do
    #     if [ -f "${CHROOT}/etc/authselect/${pam_file}" ]; then
    #         ln -sf ../authselect/${pam_file} "${CHROOT}/etc/pam.d/${pam_file}"
    #     fi
    # done

    # # Handle optional dconf (if present in profile; usually not for plain sssd)
    # if [ -f "${CHROOT}/etc/authselect/dconf-db" ]; then
    #     mkdir -p "${CHROOT}/etc/dconf/db/local.d"
    #     cp "${CHROOT}/etc/authselect/dconf-db" "${CHROOT}/etc/dconf/db/local.d/00-authselect"
    # fi
    # if [ -f "${CHROOT}/etc/authselect/dconf-lock" ]; then
    #     mkdir -p "${CHROOT}/etc/dconf/db/local.d/locks"
    #     cp "${CHROOT}/etc/authselect/dconf-lock" "${CHROOT}/etc/dconf/db/local.d/locks/00-authselect"
    # fi
    # # Note: Run 'dconf update' inside the container after starting it if dconf files were copied.

    # echo "Authselect sssd profile applied via file-level modifications."
else
    # In non-chroot environment, use the authselect command
    if [ -f /usr/bin/authselect ]; then
        authselect current

        if test "$?" -ne 0; then
            if { rpm --quiet -q kernel rpm-ostree bootc && ! rpm --quiet -q openshift-kubelet && { [ -f "/run/.containerenv" ] || [ -f "/.containerenv" ]; }; }; then
                authselect select --force "$var_authselect_profile"
            else
                authselect select "$var_authselect_profile"
            fi

            if test "$?" -ne 0; then
                if rpm --quiet --verify pam; then
                    authselect select --force "$var_authselect_profile"
                else
                    echo "authselect is not used but files from the 'pam' package have been altered, so the authselect configuration won't be forced." >&2
                fi
            fi
        fi
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_enable_authselect'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_password_auth'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_password_auth'"); (

# In chroot environment, we need to modify the files directly
AUTH_FILES=("$(get_path "/etc/pam.d/system-auth")" "$(get_path "/etc/pam.d/password-auth")")
for pam_file in "${AUTH_FILES[@]}"
do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    fi
done


) # END fix for 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_password_auth'

###############################################################################
# BEGIN fix  for 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_system_auth'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_system_auth'"); (

# In chroot environment, we need to modify the files directly
AUTH_FILES=("$(get_path "/etc/pam.d/system-auth")" "$(get_path "/etc/pam.d/password-auth")")
for pam_file in "${AUTH_FILES[@]}"
do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    fi
done

) # END fix for 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_system_auth'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_audit'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_audit'"); (

# In chroot environment, we need to modify the files directly
AUTH_FILES=("$(get_path "/etc/pam.d/system-auth")" "$(get_path "/etc/pam.d/password-auth")")
FAILLOCK_CONF="$(get_path "/etc/security/faillock.conf")"

# First ensure the basic faillock configuration is in place
for pam_file in "${AUTH_FILES[@]}"
do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    fi
done

# Now handle the audit configuration
if [ -f "$FAILLOCK_CONF" ]; then
    regex="^\s*audit"
    line="audit"
    if ! grep -q $regex "$FAILLOCK_CONF"; then
        echo $line >> "$FAILLOCK_CONF"
    fi

    # Remove audit option from PAM files if present
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\baudit\b" "$pam_file"; then
                sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\baudit\b=?[[:alnum:]]*(.*)/\1\2/g" "$pam_file"
            fi
        fi
    done
else
    # If faillock.conf doesn't exist, add audit option to PAM files
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*audit' "$pam_file"; then
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ audit/' "$pam_file"
            fi
        fi
    done
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_audit'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny'
###############################################################################
(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny'"); (
# Remediation is applicable only in certain platforms

var_accounts_passwords_pam_faillock_deny='3'

# In chroot environment, we need to modify the files directly
AUTH_FILES=("$(get_path "/etc/pam.d/system-auth")" "$(get_path "/etc/pam.d/password-auth")")
FAILLOCK_CONF="$(get_path "/etc/security/faillock.conf")"

# First ensure the basic faillock configuration is in place
for pam_file in "${AUTH_FILES[@]}"
do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    fi
done

# Now handle the deny configuration
if [ -f "$FAILLOCK_CONF" ]; then
    regex="^\s*deny\s*="
    line="deny = $var_accounts_passwords_pam_faillock_deny"
    if ! grep -q $regex "$FAILLOCK_CONF"; then
        echo $line >> "$FAILLOCK_CONF"
    else
        sed -i --follow-symlinks 's|^\s*\(deny\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_deny"'|g' "$FAILLOCK_CONF"
    fi

    # Remove deny option from PAM files if present
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\bdeny\b" "$pam_file"; then
                sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\bdeny\b=?[[:alnum:]]*(.*)/\1\2/g" "$pam_file"
            fi
        fi
    done
else
    # If faillock.conf doesn't exist, add deny option to PAM files
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*deny' "$pam_file"; then
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
            else
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
            fi
        fi
    done
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root'
###############################################################################
(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root'"); (

# In chroot environment, we need to modify the files directly
AUTH_FILES=("$(get_path "/etc/pam.d/system-auth")" "$(get_path "/etc/pam.d/password-auth")")
FAILLOCK_CONF="$(get_path "/etc/security/faillock.conf")"

# First ensure the basic faillock configuration is in place
for pam_file in "${AUTH_FILES[@]}"
do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    fi
done

# Now handle the even_deny_root configuration
if [ -f "$FAILLOCK_CONF" ]; then
    regex="^\s*even_deny_root"
    line="even_deny_root"
    if ! grep -q $regex "$FAILLOCK_CONF"; then
        echo $line >> "$FAILLOCK_CONF"
    fi

    # Remove even_deny_root option from PAM files if present
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\beven_deny_root\b" "$pam_file"; then
                sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\beven_deny_root\b=?[[:alnum:]]*(.*)/\1\2/g" "$pam_file"
            fi
        fi
    done
else
    # If faillock.conf doesn't exist, add even_deny_root option to PAM files
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*even_deny_root' "$pam_file"; then
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ even_deny_root/' "$pam_file"
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ even_deny_root/' "$pam_file"
            fi
        fi
    done
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_dir'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_dir'"); (

var_accounts_passwords_pam_faillock_dir='/var/log/faillock'

# In chroot environment, we need to modify the files directly
AUTH_FILES=("$(get_path "/etc/pam.d/system-auth")" "$(get_path "/etc/pam.d/password-auth")")
FAILLOCK_CONF="$(get_path "/etc/security/faillock.conf")"

# First ensure the basic faillock configuration is in place
for pam_file in "${AUTH_FILES[@]}"
do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    fi
done

# Now handle the dir configuration
if [ -f "$FAILLOCK_CONF" ]; then
    regex="^\s*dir\s*="
    line="dir = $var_accounts_passwords_pam_faillock_dir"
    if ! grep -q $regex "$FAILLOCK_CONF"; then
        echo $line >> "$FAILLOCK_CONF"
    else
        sed -i --follow-symlinks 's|^\s*\(dir\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_dir"'|g' "$FAILLOCK_CONF"
    fi

    # Remove dir option from PAM files if present
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\bdir\b" "$pam_file"; then
                sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\bdir\b=?[[:alnum:]]*(.*)/\1\2/g" "$pam_file"
            fi
        fi
    done
else
    # If faillock.conf doesn't exist, add dir option to PAM files
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*dir' "$pam_file"; then
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ dir='"$var_accounts_passwords_pam_faillock_dir"'/' "$pam_file"
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ dir='"$var_accounts_passwords_pam_faillock_dir"'/' "$pam_file"
            else
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"dir"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_dir"'\3/' "$pam_file"
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"dir"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_dir"'\3/' "$pam_file"
            fi
        fi
    done
fi


#mkdir -p "$var_accounts_passwords_pam_faillock_dir"
#semanage fcontext -a -t faillog_t "$var_accounts_passwords_pam_faillock_dir(/.*)?"
#restorecon -R -v "$var_accounts_passwords_pam_faillock_dir"

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_dir'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_interval'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_interval'"); (

var_accounts_passwords_pam_faillock_fail_interval='900'

# In chroot environment, we need to modify the files directly
AUTH_FILES=("$(get_path "/etc/pam.d/system-auth")" "$(get_path "/etc/pam.d/password-auth")")
FAILLOCK_CONF="$(get_path "/etc/security/faillock.conf")"

# First ensure the basic faillock configuration is in place
for pam_file in "${AUTH_FILES[@]}"
do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    fi
done

# Now handle the fail_interval configuration
if [ -f "$FAILLOCK_CONF" ]; then
    regex="^\s*fail_interval\s*="
    line="fail_interval = $var_accounts_passwords_pam_faillock_fail_interval"
    if ! grep -q $regex "$FAILLOCK_CONF"; then
        echo $line >> "$FAILLOCK_CONF"
    else
        sed -i --follow-symlinks 's|^\s*\(fail_interval\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_fail_interval"'|g' "$FAILLOCK_CONF"
    fi

    # Remove fail_interval option from PAM files if present
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\bfail_interval\b" "$pam_file"; then
                sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\bfail_interval\b=?[[:alnum:]]*(.*)/\1\2/g" "$pam_file"
            fi
        fi
    done
else
    # If faillock.conf doesn't exist, add fail_interval option to PAM files
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*fail_interval' "$pam_file"; then
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ fail_interval='"$var_accounts_passwords_pam_faillock_fail_interval"'/' "$pam_file"
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ fail_interval='"$var_accounts_passwords_pam_faillock_fail_interval"'/' "$pam_file"
            else
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"fail_interval"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_fail_interval"'\3/' "$pam_file"
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"fail_interval"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_fail_interval"'\3/' "$pam_file"
            fi
        fi
    done
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_interval'

###############################################################################
# BEGIN fix  for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time'"); (

var_accounts_passwords_pam_faillock_unlock_time='0'

# In chroot environment, we need to modify the files directly
AUTH_FILES=("$(get_path "/etc/pam.d/system-auth")" "$(get_path "/etc/pam.d/password-auth")")
FAILLOCK_CONF="$(get_path "/etc/security/faillock.conf")"

# First ensure the basic faillock configuration is in place
for pam_file in "${AUTH_FILES[@]}"
do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    fi
done

# Now handle the unlock_time configuration
if [ -f "$FAILLOCK_CONF" ]; then
    regex="^\s*unlock_time\s*="
    line="unlock_time = $var_accounts_passwords_pam_faillock_unlock_time"
    if ! grep -q $regex "$FAILLOCK_CONF"; then
        echo $line >> "$FAILLOCK_CONF"
    else
        sed -i --follow-symlinks 's|^\s*\(unlock_time\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_unlock_time"'|g' "$FAILLOCK_CONF"
    fi

    # Remove unlock_time option from PAM files if present
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\bunlock_time\b" "$pam_file"; then
                sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\bunlock_time\b=?[[:alnum:]]*(.*)/\1\2/g" "$pam_file"
            fi
        fi
    done
else
    # If faillock.conf doesn't exist, add unlock_time option to PAM files
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -f "$pam_file" ]; then
            if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*unlock_time' "$pam_file"; then
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
            else
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"unlock_time"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"unlock_time"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
            fi
        fi
    done
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dcredit'
###############################################################################
(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dcredit'"); (

var_password_pam_dcredit='-1'

# In chroot environment, modify the file directly
PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

# Remove dcredit from any conf files in the directory if they exist
if [ -d "$PWQUALITY_CONF_DIR" ]; then
    find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/dcredit/d" {} \;
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key="dcredit"

# Format the output line
formatted_output="$stripped_key = $var_password_pam_dcredit"

# If the key exists, change it. Otherwise, add it to the config_file.
if [ -f "$PWQUALITY_CONF" ]; then
    if grep -q -m 1 -i -e "^dcredit\\>" "$PWQUALITY_CONF"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        sed -i --follow-symlinks "s/^dcredit\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
    else
        if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
            sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
        fi
        cce="CCE-83566-0"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # Create the file if it doesn't exist
    mkdir -p "$(dirname "$PWQUALITY_CONF")"
    cce="CCE-83566-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
    printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dcredit'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck'"); (

var_password_pam_dictcheck='1'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify the file directly
    PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
    PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

    # Remove dictcheck from any conf files in the directory if they exist
    if [ -d "$PWQUALITY_CONF_DIR" ]; then
        find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/dictcheck/d" {} \;
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="dictcheck"

    # Format the output line
    formatted_output="$stripped_key = $var_password_pam_dictcheck"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$PWQUALITY_CONF" ]; then
        if grep -q -m 1 -i -e "^dictcheck\\>" "$PWQUALITY_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^dictcheck\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
        else
            if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
            fi
            cce="CCE-88413-0"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
            printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cce="CCE-88413-0"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # In non-chroot environment
    if grep -sq dictcheck /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/dictcheck/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^dictcheck")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_dictcheck"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^dictcheck\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^dictcheck\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-88413-0"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck'

###############################################################################
# BEGIN fix (20 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_lcredit'
###############################################################################
(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_lcredit'"); (

var_password_pam_lcredit='-1'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify the file directly
    PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
    PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

    # Remove lcredit from any conf files in the directory if they exist
    if [ -d "$PWQUALITY_CONF_DIR" ]; then
        find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/lcredit/d" {} \;
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="lcredit"

    # Format the output line
    formatted_output="$stripped_key = $var_password_pam_lcredit"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$PWQUALITY_CONF" ]; then
        if grep -q -m 1 -i -e "^lcredit\\>" "$PWQUALITY_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^lcredit\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
        else
            if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
            fi
            cce="CCE-88414-8"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
            printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cce="CCE-88414-8"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # In non-chroot environment
    if grep -sq lcredit /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/lcredit/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^lcredit")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_lcredit"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^lcredit\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^lcredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-88414-8"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_lcredit'

###############################################################################
# BEGIN fix (21 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass'
###############################################################################
(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass'"); (

var_password_pam_minclass='4'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify the file directly
    PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
    PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

    # Remove minclass from any conf files in the directory if they exist
    if [ -d "$PWQUALITY_CONF_DIR" ]; then
        find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/minclass/d" {} \;
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="minclass"

    # Format the output line
    formatted_output="$stripped_key = $var_password_pam_minclass"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$PWQUALITY_CONF" ]; then
        if grep -q -m 1 -i -e "^minclass\\>" "$PWQUALITY_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^minclass\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
        else
            if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
            fi
            cce="CCE-88415-5"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
            printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cce="CCE-88415-5"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # In non-chroot environment
    if grep -sq minclass /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/minclass/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minclass")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minclass"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^minclass\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^minclass\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-88415-5"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass'

###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen'"); (

var_password_pam_minlen='15'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify the file directly
    PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
    PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

    # Remove minlen from any conf files in the directory if they exist
    if [ -d "$PWQUALITY_CONF_DIR" ]; then
        find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/minlen/d" {} \;
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="minlen"

    # Format the output line
    formatted_output="$stripped_key = $var_password_pam_minlen"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$PWQUALITY_CONF" ]; then
        if grep -q -m 1 -i -e "^minlen\\>" "$PWQUALITY_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^minlen\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
        else
            if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
            fi
            cce="CCE-88416-3"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
            printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cce="CCE-88416-3"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # In non-chroot environment
    if grep -sq minlen /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/minlen/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minlen")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minlen"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^minlen\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^minlen\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-88416-3"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen'

###############################################################################
# BEGIN fix (23 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_ocredit'
###############################################################################
(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_ocredit'"); (

var_password_pam_ocredit='-1'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify the file directly
    PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
    PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

    # Remove ocredit from any conf files in the directory if they exist
    if [ -d "$PWQUALITY_CONF_DIR" ]; then
        find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/ocredit/d" {} \;
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="ocredit"

    # Format the output line
    formatted_output="$stripped_key = $var_password_pam_ocredit"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$PWQUALITY_CONF" ]; then
        if grep -q -m 1 -i -e "^ocredit\\>" "$PWQUALITY_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^ocredit\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
        else
            if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
            fi
            cce="CCE-88417-1"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
            printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cce="CCE-88417-1"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # In non-chroot environment
    if grep -sq ocredit /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/ocredit/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ocredit")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ocredit"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^ocredit\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^ocredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-88417-1"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_ocredit'

###############################################################################
# BEGIN fix (24 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_retry'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_password_pam_retry'"); (

var_password_pam_retry='3'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify the file directly
    PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
    PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

    # Remove retry from any conf files in the directory if they exist
    if [ -d "$PWQUALITY_CONF_DIR" ]; then
        find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/retry/d" {} \;
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="retry"

    # Format the output line
    formatted_output="$stripped_key = $var_password_pam_retry"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$PWQUALITY_CONF" ]; then
        if grep -q -m 1 -i -e "^retry\\>" "$PWQUALITY_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^retry\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
        else
            if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
            fi
            cce="CCE-88418-9"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
            printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cce="CCE-88418-9"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # In non-chroot environment
    if grep -sq retry /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/retry/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^retry")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_retry"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^retry\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^retry\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-88418-9"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_retry'

###############################################################################
# BEGIN fix (25 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_ucredit'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_password_pam_ucredit'"); (

var_password_pam_ucredit='-1'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify the file directly
    PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
    PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

    # Remove ucredit from any conf files in the directory if they exist
    if [ -d "$PWQUALITY_CONF_DIR" ]; then
        find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/ucredit/d" {} \;
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="ucredit"

    # Format the output line
    formatted_output="$stripped_key = $var_password_pam_ucredit"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$PWQUALITY_CONF" ]; then
        if grep -q -m 1 -i -e "^ucredit\\>" "$PWQUALITY_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^ucredit\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
        else
            if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
            fi
            cce="CCE-88419-7"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
            printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cce="CCE-88419-7"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # In non-chroot environment
    if grep -sq ucredit /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/ucredit/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ucredit")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ucredit"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^ucredit\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^ucredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-88419-7"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_ucredit'

###############################################################################
# BEGIN fix (26 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_tmout'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_tmout'"); (

var_accounts_tmout='900'

# In chroot environment, modify files directly
PROFILE_D="$(get_path "/etc/profile.d")"
BASHRC="$(get_path "/etc/bashrc")"
CSHRC="$(get_path "/etc/csh.cshrc")"

# Create or update /etc/profile.d/tmout.sh
mkdir -p "$PROFILE_D"
cat <<EOF > "$PROFILE_D/tmout.sh"
# Set a 15 minute timeout policy for bash shell
readonly TMOUT=$var_accounts_tmout
export TMOUT
EOF

# Create or update /etc/profile.d/tmout.csh
cat <<EOF > "$PROFILE_D/tmout.csh"
# Set a 15 minute timeout policy for csh shell
set autologout=$((var_accounts_tmout/60))
EOF

# Make the files executable
chmod +x "$PROFILE_D/tmout.sh" "$PROFILE_D/tmout.csh"

# Add timeout to /etc/bashrc if it exists
if [ -f "$BASHRC" ]; then
    if ! grep -q "^readonly TMOUT=" "$BASHRC"; then
        echo -e "\n# Set a 15 minute timeout policy for bash shell\nreadonly TMOUT=$var_accounts_tmout\nexport TMOUT" >> "$BASHRC"
    fi
fi

# Add timeout to /etc/csh.cshrc if it exists
if [ -f "$CSHRC" ]; then
    if ! grep -q "^set autologout=" "$CSHRC"; then
        echo -e "\n# Set a 15 minute timeout policy for csh shell\nset autologout=$((var_accounts_tmout/60))" >> "$CSHRC"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_tmout'

###############################################################################
# BEGIN fix (27 / 45) for 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'"); (

var_system_crypto_policy='FIPS'

# In chroot environment, modify files directly
CRYPTO_POLICY_CONFIG="$(get_path "/etc/crypto-policies/config")"
CRYPTO_POLICIES_DIR="$(get_path "/usr/share/crypto-policies")"
CRYPTO_POLICIES_STATE="$(get_path "/etc/crypto-policies/state")"
CRYPTO_POLICIES_BACKENDS="$(get_path "/etc/crypto-policies/back-ends")"

# Check if the crypto-policies directory exists
if [ -d "$CRYPTO_POLICIES_DIR" ]; then
    # Check if the specified policy exists
    if [ -d "$CRYPTO_POLICIES_DIR/policies/$var_system_crypto_policy" ]; then
        # Create the config directory if it doesn't exist
        mkdir -p "$(dirname "$CRYPTO_POLICY_CONFIG")"
        mkdir -p "$CRYPTO_POLICIES_STATE"

        # Set the crypto policy
        echo "$var_system_crypto_policy" > "$CRYPTO_POLICY_CONFIG"

        # Update the current state file
        echo "$var_system_crypto_policy" > "$CRYPTO_POLICIES_STATE/current"

        # Update symbolic links in back-ends directory to point to FIPS
        if [ -d "$CRYPTO_POLICIES_BACKENDS" ]; then
            # First ensure the directory exists
            mkdir -p "$CRYPTO_POLICIES_BACKENDS"

            # Create or update the symbolic links for specific files
            ln -sf "/usr/share/crypto-policies/$var_system_crypto_policy/opensslcnf.txt" "$CRYPTO_POLICIES_BACKENDS/opensslcnf.config"
            ln -sf "/usr/share/crypto-policies/$var_system_crypto_policy/openssl_fips.txt" "$CRYPTO_POLICIES_BACKENDS/openssl_fips.config"

            # Update other config files if they exist
            for config_file in "$CRYPTO_POLICIES_BACKENDS"/*.config; do
                if [ -L "$config_file" ] && [ "$(basename "$config_file")" != "opensslcnf.config" ] && [ "$(basename "$config_file")" != "openssl_fips.config" ]; then
                    base_name=$(basename "$config_file")
                    target_file="/usr/share/crypto-policies/$var_system_crypto_policy/${base_name%.config}.txt"
                    if [ -f "$(get_path "$target_file")" ]; then
                        ln -sf "$target_file" "$config_file"
                    fi
                fi
            done
        fi

        # In a chroot environment, we can't run update-crypto-policies
        # This will need to be run after exiting the chroot
        echo "NOTE: In chroot environment - crypto policy set to $var_system_crypto_policy but update-crypto-policies needs to be run after exiting chroot" >&2
    else
        echo "Error: Crypto policy $var_system_crypto_policy does not exist in $CRYPTO_POLICIES_DIR/policies/" >&2

    fi
else
    echo "Error: Crypto policies directory $CRYPTO_POLICIES_DIR does not exist" >&2

fi


) # END fix for 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'

###############################################################################
# BEGIN fix (28 / 45) for 'xccdf_org.ssgproject.content_rule_coredump_disable_backtraces'
###############################################################################
(>&2 echo "Remediating rule 28/45: 'xccdf_org.ssgproject.content_rule_coredump_disable_backtraces'"); (

# In chroot environment, modify files directly
SYSCTL_CONF_DIR="$(get_path "/etc/sysctl.d")"

# Create the directory if it doesn't exist
mkdir -p "$SYSCTL_CONF_DIR"

# Create or update the sysctl configuration file
cat << EOF > "$SYSCTL_CONF_DIR/50-coredump.conf"
# Disable core dumps
kernel.core_pattern=|/bin/false
kernel.core_uses_pid=0
fs.suid_dumpable=0
# Disable backtraces
kernel.kptr_restrict=2
EOF

# In a chroot environment, we can't apply the settings directly
echo "NOTE: In chroot environment - sysctl settings configured but need to be applied after exiting chroot" >&2


) # END fix for 'xccdf_org.ssgproject.content_rule_coredump_disable_backtraces'

###############################################################################
# BEGIN fix (29 / 45) for 'xccdf_org.ssgproject.content_rule_coredump_disable_storage'
###############################################################################
(>&2 echo "Remediating rule 29/45: 'xccdf_org.ssgproject.content_rule_coredump_disable_storage'"); (

# In chroot environment, modify files directly
SYSTEMD_COREDUMP_CONF="$(get_path "/etc/systemd/coredump.conf")"
SYSTEMD_COREDUMP_CONF_DIR="$(get_path "/etc/systemd/coredump.conf.d")"

# Create the directory if it doesn't exist
mkdir -p "$SYSTEMD_COREDUMP_CONF_DIR"

# Create or update the coredump configuration file
cat << EOF > "$SYSTEMD_COREDUMP_CONF_DIR/disable.conf"
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

# If the main config file exists, ensure it doesn't override our settings
if [ -f "$SYSTEMD_COREDUMP_CONF" ]; then
    # Comment out any Storage or ProcessSizeMax lines
    sed -i 's/^\(Storage=.*\)/#\1/' "$SYSTEMD_COREDUMP_CONF"
    sed -i 's/^\(ProcessSizeMax=.*\)/#\1/' "$SYSTEMD_COREDUMP_CONF"
fi

# In a chroot environment, we can't restart systemd-coredump
echo " coredump settings configured but systemd-coredump needs to be restarted after exiting chroot" >&2


) # END fix for 'xccdf_org.ssgproject.content_rule_coredump_disable_storage'

###############################################################################
# BEGIN fix (30 / 45) for 'xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_burstaction'
###############################################################################
(>&2 echo "Remediating rule 30/45: 'xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_burstaction'"); (

# In chroot environment, modify files directly
SYSTEMD_SYSTEM_CONF="$(get_path "/etc/systemd/system.conf")"
SYSTEMD_SYSTEM_CONF_DIR="$(get_path "/etc/systemd/system.conf.d")"

# Create the directory if it doesn't exist
mkdir -p "$SYSTEMD_SYSTEM_CONF_DIR"

# Create or update the systemd configuration file
cat << EOF > "$SYSTEMD_SYSTEM_CONF_DIR/disable-ctrl-alt-del.conf"
[Manager]
CtrlAltDelBurstAction=none
EOF

# If the main config file exists, ensure it doesn't override our settings
if [ -f "$SYSTEMD_SYSTEM_CONF" ]; then
    # Comment out any CtrlAltDelBurstAction lines
    sed -i 's/^\(CtrlAltDelBurstAction=.*\)/#\1/' "$SYSTEMD_SYSTEM_CONF"
fi

# In a chroot environment, we can't reload systemd
echo "NOTE: systemd settings configured but systemd needs to be reloaded after exiting chroot" >&2

) # END fix for 'xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_burstaction'

###############################################################################
# BEGIN fix (31 / 45) for 'xccdf_org.ssgproject.content_rule_disable_users_coredumps'
###############################################################################
(>&2 echo "Remediating rule 31/45: 'xccdf_org.ssgproject.content_rule_disable_users_coredumps'"); (

# In chroot environment, modify files directly
LIMITS_CONF="$(get_path "/etc/security/limits.conf")"
LIMITS_D="$(get_path "/etc/security/limits.d")"

# Create the directory if it doesn't exist
mkdir -p "$LIMITS_D"

# Create or update the limits configuration file
cat << EOF > "$LIMITS_D/50-coredump.conf"
# Disable core dumps for all users
* hard core 0
EOF

# If the main config file exists, ensure it doesn't override our settings
if [ -f "$LIMITS_CONF" ]; then
    # Remove any existing core dump limits
    sed -i '/^.*[[:space:]]\+hard[[:space:]]\+core[[:space:]]\+/d' "$LIMITS_CONF"
    # Add our limit at the end
    echo "# Disable core dumps for all users" >> "$LIMITS_CONF"
    echo "* hard core 0" >> "$LIMITS_CONF"
fi

# Configure sysctl settings
SYSCTL_CONF_DIR="$(get_path "/etc/sysctl.d")"
mkdir -p "$SYSCTL_CONF_DIR"

cat << EOF > "$SYSCTL_CONF_DIR/50-coredump.conf"
# Disable core dumps
fs.suid_dumpable=0
EOF

# In a chroot environment, we can't apply the sysctl settings
echo "NOTE: In chroot environment - sysctl settings configured but need to be applied after exiting chroot" >&2

) # END fix for 'xccdf_org.ssgproject.content_rule_disable_users_coredumps'

###############################################################################
# BEGIN fix (32 / 45) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_group'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_group'"); (

# In chroot environment, modify files directly
ETC_GROUP="$(get_path "/etc/group")"

# Check if the file exists
if [ -f "$ETC_GROUP" ]; then
    # Set the group owner to root
    chgrp root "$ETC_GROUP"
else
    echo "Error: $ETC_GROUP does not exist" >&2

fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_group'

###############################################################################
# BEGIN fix (33 / 45) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd'"); (

ETC_PASSWD="$(get_path "/etc/passwd")"

# Check if the file exists
if [ -f "$ETC_PASSWD" ]; then
    # Set the group owner to root
    chgrp root "$ETC_PASSWD"
else
    echo "Error: $ETC_PASSWD does not exist" >&2
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd'

###############################################################################
# BEGIN fix (34 / 45) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_group'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_file_owner_etc_group'"); (

# In chroot environment, modify files directly
ETC_GROUP="$(get_path "/etc/group")"

# Check if the file exists
if [ -f "$ETC_GROUP" ]; then
    # Set the owner to root
    chown root "$ETC_GROUP"
else
    echo "Error: $ETC_GROUP does not exist" >&2
fi


) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_group'

###############################################################################
# BEGIN fix (35 / 45) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_file_owner_etc_passwd'"); (

# In chroot environment, modify files directly
ETC_PASSWD="$(get_path "/etc/passwd")"

# Check if the file exists
if [ -f "$ETC_PASSWD" ]; then
    # Set the owner to root
    chown root "$ETC_PASSWD"
else
    echo "Error: $ETC_PASSWD does not exist" >&2
fi


) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_passwd'

###############################################################################
# BEGIN fix (36 / 45) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_group'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_file_permissions_etc_group'"); (

# In chroot environment, modify files directly
ETC_GROUP="$(get_path "/etc/group")"

# Check if the file exists
if [ -f "$ETC_GROUP" ]; then
    # Set the permissions to 0644
    chmod 0644 "$ETC_GROUP"
else
    echo "Error: $ETC_GROUP does not exist" >&2
fi


) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_group'

###############################################################################
# BEGIN fix (37 / 45) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule 37/45: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd'"); (

# In chroot environment, modify files directly
ETC_PASSWD="$(get_path "/etc/passwd")"

# Check if the file exists
if [ -f "$ETC_PASSWD" ]; then
    # Set the permissions to 0644
    chmod 0644 "$ETC_PASSWD"
else
    echo "Error: $ETC_PASSWD does not exist" >&2
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd'

###############################################################################
# BEGIN fix (38 / 45) for 'xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled'
###############################################################################
(>&2 echo "Remediating rule 38/45: 'xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled'"); (

# In chroot environment, modify files directly
MODPROBE_CONF_DIR="$(get_path "/etc/modprobe.d")"

# Create the directory if it doesn't exist
mkdir -p "$MODPROBE_CONF_DIR"

# Create or update the modprobe configuration file
cat << EOF > "$MODPROBE_CONF_DIR/cramfs.conf"
# Disable cramfs module
install cramfs /bin/false
blacklist cramfs
EOF

# In a chroot environment, we can't run modprobe
echo "NOTE: In chroot environment - cramfs module disabled in configuration but needs to be unloaded after exiting chroot" >&2


) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled'

###############################################################################
# BEGIN fix (39 / 45) for 'xccdf_org.ssgproject.content_rule_kernel_module_squashfs_disabled'
###############################################################################
(>&2 echo "Remediating rule 39/45: 'xccdf_org.ssgproject.content_rule_kernel_module_squashfs_disabled'"); (

# In chroot environment, modify files directly
MODPROBE_CONF_DIR="$(get_path "/etc/modprobe.d")"

# Create the directory if it doesn't exist
mkdir -p "$MODPROBE_CONF_DIR"

# Create or update the modprobe configuration file
cat << EOF > "$MODPROBE_CONF_DIR/squashfs.conf"
# Disable squashfs module
install squashfs /bin/false
blacklist squashfs
EOF

# In a chroot environment, we can't run modprobe
echo "NOTE: In chroot environment - squashfs module disabled in configuration but needs to be unloaded after exiting chroot" >&2

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_squashfs_disabled'

###############################################################################
# BEGIN fix (40 / 45) for 'xccdf_org.ssgproject.content_rule_kernel_module_udf_disabled'
###############################################################################
(>&2 echo "Remediating rule 40/45: 'xccdf_org.ssgproject.content_rule_kernel_module_udf_disabled'"); (

# In chroot environment, modify files directly
MODPROBE_CONF_DIR="$(get_path "/etc/modprobe.d")"

# Create the directory if it doesn't exist
mkdir -p "$MODPROBE_CONF_DIR"

# Create or update the modprobe configuration file
cat << EOF > "$MODPROBE_CONF_DIR/udf.conf"
# Disable udf module
install udf /bin/false
blacklist udf
EOF

# In a chroot environment, we can't run modprobe
echo "NOTE: In chroot environment - udf module disabled in configuration but needs to be unloaded after exiting chroot" >&2


) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_udf_disabled'

###############################################################################
# BEGIN fix (41 / 45) for 'xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled'
###############################################################################
(>&2 echo "Remediating rule 41/45: 'xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled'"); (

# In chroot environment, modify files directly
MODPROBE_CONF_DIR="$(get_path "/etc/modprobe.d")"

# Create the directory if it doesn't exist
mkdir -p "$MODPROBE_CONF_DIR"

# Create or update the modprobe configuration file
cat << EOF > "$MODPROBE_CONF_DIR/usb-storage.conf"
# Disable usb-storage module
install usb-storage /bin/false
blacklist usb-storage
EOF

# In a chroot environment, we can't run modprobe
echo "NOTE: In chroot environment - usb-storage module disabled in configuration but needs to be unloaded after exiting chroot" >&2


) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled'



###############################################################################
# BEGIN fix for 'xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space'"); (

var_sysctl_kernel_randomize_va_space='2'

# In chroot environment, modify files directly
SYSCTL_CONF_DIR="$(get_path "/etc/sysctl.d")"

# Create the directory if it doesn't exist
mkdir -p "$SYSCTL_CONF_DIR"

# Create or update the sysctl configuration file
cat << EOF > "$SYSCTL_CONF_DIR/10-va-randomization.conf"
# Enable virtual address space randomization
kernel.randomize_va_space = $var_sysctl_kernel_randomize_va_space
EOF

# In a chroot environment, we can't apply the settings directly
echo "NOTE: In chroot environment - sysctl settings configured but need to be applied after exiting chroot" >&2


) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space'

###############################################################################
# BEGIN fix (45 / 45) for 'xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope'"); (

var_sysctl_kernel_yama_ptrace_scope='1'

# In chroot environment, modify files directly
SYSCTL_CONF_DIR="$(get_path "/etc/sysctl.d")"

# Create the directory if it doesn't exist
mkdir -p "$SYSCTL_CONF_DIR"

# Create or update the sysctl configuration file
cat << EOF > "$SYSCTL_CONF_DIR/10-ptrace-scope.conf"
# Set ptrace scope
kernel.yama.ptrace_scope = $var_sysctl_kernel_yama_ptrace_scope
EOF

# In a chroot environment, we can't apply the settings directly
echo "NOTE: In chroot environment - sysctl settings configured but need to be applied after exiting chroot" >&2

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope'


###############################################################################
# BEGIN fix (5 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_difok'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_password_pam_difok'"); (

var_password_pam_difok='8'

if grep -sq difok $CHROOT/etc/security/pwquality.conf.d/*.conf ; then
    sed -i "/difok/d" $CHROOT/etc/security/pwquality.conf.d/*.conf
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^difok")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_difok"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^difok\\>" "$CHROOT/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^difok\\>.*/$escaped_formatted_output/gi" "$CHROOT/etc/security/pwquality.conf"
else
    if [[ -s "$CHROOT/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "$CHROOT/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$CHROOT/etc/security/pwquality.conf"
    fi
    cce="CCE-83564-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$CHROOT/etc/security/pwquality.conf" >> "$CHROOT/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "$CHROOT/etc/security/pwquality.conf"
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_difok'

###############################################################################
# BEGIN fix (6 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root'"); (

    # In chroot environment
    if [ -e "$CHROOT/etc/security/pwquality.conf" ] ; then
        LC_ALL=C sed -i "/^\s*enforce_for_root/Id" "$CHROOT/etc/security/pwquality.conf"
    else
        touch "$CHROOT/etc/security/pwquality.conf"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "$CHROOT/etc/security/pwquality.conf"

    cp "$CHROOT/etc/security/pwquality.conf" "$CHROOT/etc/security/pwquality.conf.bak"
    # Insert at the end of the file
    printf '%s\n' "enforce_for_root" >> "$CHROOT/etc/security/pwquality.conf"
    # Clean up after ourselves.
    rm "$CHROOT/etc/security/pwquality.conf.bak"



) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root'

###############################################################################
# BEGIN fix (7 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxclassrepeat'
###############################################################################
(>&2 echo "Remediating rule 7/45: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxclassrepeat'"); (

var_password_pam_maxclassrepeat='4'

    # In chroot environment
    if grep -sq maxclassrepeat $CHROOT/etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/maxclassrepeat/d" $CHROOT/etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^maxclassrepeat")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_maxclassrepeat"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^maxclassrepeat\\>" "$CHROOT/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^maxclassrepeat\\>.*/$escaped_formatted_output/gi" "$CHROOT/etc/security/pwquality.conf"
    else
        if [[ -s "$CHROOT/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "$CHROOT/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "$CHROOT/etc/security/pwquality.conf"
        fi
        cce="CCE-83575-1"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$CHROOT/etc/security/pwquality.conf" >> "$CHROOT/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "$CHROOT/etc/security/pwquality.conf"
    fi


) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxclassrepeat'

###############################################################################
# BEGIN fix (8 / 46) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat'
###############################################################################
(>&2 echo "Remediating rule 8/46: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat'"); (

var_password_pam_maxrepeat='3'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify the file directly
    PWQUALITY_CONF="$(get_path "/etc/security/pwquality.conf")"
    PWQUALITY_CONF_DIR="$(get_path "/etc/security/pwquality.conf.d")"

    # Remove maxrepeat from any conf files in the directory if they exist
    if [ -d "$PWQUALITY_CONF_DIR" ]; then
        find "$PWQUALITY_CONF_DIR" -name "*.conf" -type f -exec sed -i "/maxrepeat/d" {} \;
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="maxrepeat"

    # Format the output line
    formatted_output="$stripped_key = $var_password_pam_maxrepeat"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$PWQUALITY_CONF" ]; then
        if grep -q -m 1 -i -e "^maxrepeat\\>" "$PWQUALITY_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^maxrepeat\\>.*/$escaped_formatted_output/gi" "$PWQUALITY_CONF"
        else
            if [[ -s "$PWQUALITY_CONF" ]] && [[ -n "$(tail -c 1 -- "$PWQUALITY_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$PWQUALITY_CONF"
            fi
            cce="CCE-83567-8"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" >> "$PWQUALITY_CONF"
            printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$PWQUALITY_CONF")"
        cce="CCE-83567-8"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$PWQUALITY_CONF" > "$PWQUALITY_CONF"
        printf '%s\n' "$formatted_output" >> "$PWQUALITY_CONF"
    fi
else
    # In non-chroot environment
    if grep -sq maxrepeat /etc/security/pwquality.conf.d/*.conf; then
        sed -i "/maxrepeat/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^maxrepeat")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_maxrepeat"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^maxrepeat\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^maxrepeat\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-83567-8"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi
fi

)
# END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat'


###############################################################################
# BEGIN fix (10 / 45) for 'xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration'
###############################################################################
(>&2 echo "Remediating rule 10/45: 'xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration'"); (

var_account_disable_post_pw_expiration='35'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify files directly
    USERADD_CONF="$(get_path "/etc/default/useradd")"

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="INACTIVE"

    # Format the output line
    formatted_output="$stripped_key=$var_account_disable_post_pw_expiration"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$USERADD_CONF" ]; then
        if grep -q -m 1 -i -e "^INACTIVE\\>" "$USERADD_CONF"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^INACTIVE\\>.*/$escaped_formatted_output/gi" "$USERADD_CONF"
        else
            if [[ -s "$USERADD_CONF" ]] && [[ -n "$(tail -c 1 -- "$USERADD_CONF" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$USERADD_CONF"
            fi
            cce="CCE-83627-0"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$USERADD_CONF" >> "$USERADD_CONF"
            printf '%s\n' "$formatted_output" >> "$USERADD_CONF"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$USERADD_CONF")"
        cce="CCE-83627-0"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$USERADD_CONF" > "$USERADD_CONF"
        printf '%s\n' "$formatted_output" >> "$USERADD_CONF"
    fi
else
    # In non-chroot environment
    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^INACTIVE")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s=%s" "$stripped_key" "$var_account_disable_post_pw_expiration"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^INACTIVE\\>" "/etc/default/useradd"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^INACTIVE\\>.*/$escaped_formatted_output/gi" "/etc/default/useradd"
    else
        if [[ -s "/etc/default/useradd" ]] && [[ -n "$(tail -c 1 -- "/etc/default/useradd" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/default/useradd"
        fi
        cce="CCE-83627-0"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/default/useradd" >> "/etc/default/useradd"
        printf '%s\n' "$formatted_output" >> "/etc/default/useradd"
    fi
fi


) # END fix for 'xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration'

###############################################################################
# BEGIN fix (11 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs'
###############################################################################
(>&2 echo "Remediating rule 11/45: 'xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs'"); (

var_accounts_maximum_age_login_defs='60'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify files directly
    LOGIN_DEFS="$(get_path "/etc/login.defs")"

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="PASS_MAX_DAYS"

    # Format the output line
    formatted_output="$stripped_key $var_accounts_maximum_age_login_defs"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$LOGIN_DEFS" ]; then
        if grep -q -m 1 -i -e "^PASS_MAX_DAYS\\>" "$LOGIN_DEFS"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^PASS_MAX_DAYS\\>.*/$escaped_formatted_output/gi" "$LOGIN_DEFS"
        else
            if [[ -s "$LOGIN_DEFS" ]] && [[ -n "$(tail -c 1 -- "$LOGIN_DEFS" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$LOGIN_DEFS"
            fi
            cce="CCE-83606-4"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$LOGIN_DEFS" >> "$LOGIN_DEFS"
            printf '%s\n' "$formatted_output" >> "$LOGIN_DEFS"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$LOGIN_DEFS")"
        cce="CCE-83606-4"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$LOGIN_DEFS" > "$LOGIN_DEFS"
        printf '%s\n' "$formatted_output" >> "$LOGIN_DEFS"
    fi
else
    # In non-chroot environment
    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_MAX_DAYS")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_maximum_age_login_defs"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^PASS_MAX_DAYS\\>" "/etc/login.defs"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^PASS_MAX_DAYS\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
    else
        if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
        fi
        cce="CCE-83606-4"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
        printf '%s\n' "$formatted_output" >> "/etc/login.defs"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs'

###############################################################################
# BEGIN fix (12 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs'
###############################################################################
(>&2 echo "Remediating rule 12/45: 'xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs'"); (

var_accounts_minimum_age_login_defs='1'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify files directly
    LOGIN_DEFS="$(get_path "/etc/login.defs")"

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key="PASS_MIN_DAYS"

    # Format the output line
    formatted_output="$stripped_key $var_accounts_minimum_age_login_defs"

    # If the key exists, change it. Otherwise, add it to the config_file.
    if [ -f "$LOGIN_DEFS" ]; then
        if grep -q -m 1 -i -e "^PASS_MIN_DAYS\\>" "$LOGIN_DEFS"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            sed -i --follow-symlinks "s/^PASS_MIN_DAYS\\>.*/$escaped_formatted_output/gi" "$LOGIN_DEFS"
        else
            if [[ -s "$LOGIN_DEFS" ]] && [[ -n "$(tail -c 1 -- "$LOGIN_DEFS" || true)" ]]; then
                sed -i --follow-symlinks '$a'\\ "$LOGIN_DEFS"
            fi
            cce="CCE-83610-6"
            printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$LOGIN_DEFS" >> "$LOGIN_DEFS"
            printf '%s\n' "$formatted_output" >> "$LOGIN_DEFS"
        fi
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$LOGIN_DEFS")"
        cce="CCE-83610-6"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$LOGIN_DEFS" > "$LOGIN_DEFS"
        printf '%s\n' "$formatted_output" >> "$LOGIN_DEFS"
    fi
else
    # In non-chroot environment
    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_MIN_DAYS")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_minimum_age_login_defs"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^PASS_MIN_DAYS\\>" "/etc/login.defs"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^PASS_MIN_DAYS\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
    else
        if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
        fi
        cce="CCE-83610-6"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
        printf '%s\n' "$formatted_output" >> "/etc/login.defs"
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs'
###############################################################################
# BEGIN fix (13 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_rounds_password_auth'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_rounds_password_auth'"); (

var_password_pam_unix_rounds='100000'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify files directly
    PAM_FILE_PATH="$(get_path "/etc/pam.d/password-auth")"

    # Check if the file exists
    if [ -f "$PAM_FILE_PATH" ]; then
        # Check if the password line with pam_unix.so exists
        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_unix.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_unix.so.*)/\1sufficient \2/" "$PAM_FILE_PATH"
            else
                echo "password    sufficient    pam_unix.so" >> "$PAM_FILE_PATH"
            fi
        fi

        # Check the option
        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*\srounds\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "/\s*password\s+sufficient\s+pam_unix.so.*/ s/$/ rounds=$var_password_pam_unix_rounds/" "$PAM_FILE_PATH"
        else
            sed -i -E --follow-symlinks "s/(\s*password\s+sufficient\s+pam_unix.so\s+.*)(rounds=)[[:alnum:]]*\s*(.*)/\1\2$var_password_pam_unix_rounds \3/" "$PAM_FILE_PATH"
        fi
    else
        # Create the directory if it doesn't exist
        mkdir -p "$(dirname "$PAM_FILE_PATH")"

        # Create a basic PAM file with the required configuration
        cat << EOF > "$PAM_FILE_PATH"
# Generated by docker-hardening-oscap.sh
password    sufficient    pam_unix.so rounds=$var_password_pam_unix_rounds
EOF
        echo "Created new password-auth file with rounds configuration" >&2
    fi
else
    # In non-chroot environment
    if [ -e "/etc/pam.d/password-auth" ] ; then
        PAM_FILE_PATH="/etc/pam.d/password-auth"
        if [ -f /usr/bin/authselect ]; then

            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                # The "local" profile does not contain essential security features required by multiple Benchmarks.
                # If currently used, it is replaced by "sssd", which is the best option in this case.
                if [[ $CURRENT_PROFILE == local ]]; then
                    CURRENT_PROFILE="sssd"
                fi
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"

                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done

                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b
        fi

        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_unix.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_unix.so.*)/\1sufficient \2/" "$PAM_FILE_PATH"
            else
                echo "password    sufficient    pam_unix.so" >> "$PAM_FILE_PATH"
            fi
        fi
        # Check the option
        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*\srounds\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "/\s*password\s+sufficient\s+pam_unix.so.*/ s/$/ rounds=$var_password_pam_unix_rounds/" "$PAM_FILE_PATH"
        else
            sed -i -E --follow-symlinks "s/(\s*password\s+sufficient\s+pam_unix.so\s+.*)(rounds=)[[:alnum:]]*\s*(.*)/\1\2$var_password_pam_unix_rounds \3/" "$PAM_FILE_PATH"
        fi
        if [ -f /usr/bin/authselect ]; then
            authselect apply-changes -b
        fi
    else
        echo "/etc/pam.d/password-auth was not found" >&2
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_rounds_password_auth'
###############################################################################
# BEGIN fix (14 / 45) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_rounds_system_auth'
###############################################################################
(>&2 echo "Remediating rule 14/45: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_rounds_system_auth'"); (

var_password_pam_unix_rounds='100000'

if [ -n "$CHROOT" ]; then
    # In chroot environment, modify files directly
    PAM_FILE_PATH="$(get_path "/etc/pam.d/system-auth")"

    # Check if the file exists
    if [ -f "$PAM_FILE_PATH" ]; then
        # Check if the password line with pam_unix.so exists
        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_unix.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_unix.so.*)/\1sufficient \2/" "$PAM_FILE_PATH"
            else
                echo "password    sufficient    pam_unix.so" >> "$PAM_FILE_PATH"
            fi
        fi

        # Check the option
        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*\srounds\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "/\s*password\s+sufficient\s+pam_unix.so.*/ s/$/ rounds=$var_password_pam_unix_rounds/" "$PAM_FILE_PATH"
        else
            sed -i -E --follow-symlinks "s/(\s*password\s+sufficient\s+pam_unix.so\s+.*)(rounds=)[[:alnum:]]*\s*(.*)/\1\2$var_password_pam_unix_rounds \3/" "$PAM_FILE_PATH"
        fi
    else
        # Create the directory if it doesn't exist
        mkdir -p "$(dirname "$PAM_FILE_PATH")"

        # Create a basic PAM file with the required configuration
        cat << EOF > "$PAM_FILE_PATH"
# Generated by docker-hardening-oscap.sh
password    sufficient    pam_unix.so rounds=$var_password_pam_unix_rounds
EOF
        echo "Created new system-auth file with rounds configuration" >&2
    fi
else
    # In non-chroot environment
    if [ -e "/etc/pam.d/system-auth" ] ; then
        PAM_FILE_PATH="/etc/pam.d/system-auth"
        if [ -f /usr/bin/authselect ]; then

            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                # The "local" profile does not contain essential security features required by multiple Benchmarks.
                # If currently used, it is replaced by "sssd", which is the best option in this case.
                if [[ $CURRENT_PROFILE == local ]]; then
                    CURRENT_PROFILE="sssd"
                fi
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"

                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done

                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b
        fi

        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_unix.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_unix.so.*)/\1sufficient \2/" "$PAM_FILE_PATH"
            else
                echo "password    sufficient    pam_unix.so" >> "$PAM_FILE_PATH"
            fi
        fi
        # Check the option
        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*\srounds\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "/\s*password\s+sufficient\s+pam_unix.so.*/ s/$/ rounds=$var_password_pam_unix_rounds/" "$PAM_FILE_PATH"
        else
            sed -i -E --follow-symlinks "s/(\s*password\s+sufficient\s+pam_unix.so\s+.*)(rounds=)[[:alnum:]]*\s*(.*)/\1\2$var_password_pam_unix_rounds \3/" "$PAM_FILE_PATH"
        fi
        if [ -f /usr/bin/authselect ]; then
            authselect apply-changes -b
        fi
    else
        echo "/etc/pam.d/system-auth was not found" >&2
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_rounds_system_auth'

###############################################################################
# BEGIN fix (15 / 45) for 'xccdf_org.ssgproject.content_rule_use_pam_wheel_for_su'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_use_pam_wheel_for_su'"); (
# uncomment the option if commented
sed '/^[[:space:]]*#[[:space:]]*auth[[:space:]]\+required[[:space:]]\+pam_wheel\.so[[:space:]]\+use_uid$/s/^[[:space:]]*#//' -i $CHROOT/etc/pam.d/su

) # END fix for 'xccdf_org.ssgproject.content_rule_use_pam_wheel_for_su'

###############################################################################
# BEGIN fix (16 / 23) for 'xccdf_org.ssgproject.content_rule_accounts_logon_fail_delay'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_logon_fail_delay'"); (

var_accounts_fail_delay='4'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^FAIL_DELAY")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_fail_delay"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^FAIL_DELAY\\>" "$CHROOT/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^FAIL_DELAY\\>.*/$escaped_formatted_output/gi" "$CHROOT/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "$CHROOT/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$CHROOT/etc/login.defs"
    fi
    cce="CCE-83635-3"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$CHROOT/etc/login.defs" >> "$CHROOT/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "$CHROOT/etc/login.defs"
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_logon_fail_delay'

###############################################################################
# BEGIN fix (17 / 23) for 'xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions'"); (

var_accounts_max_concurrent_login_sessions='10'


if grep -q '^[^#]*\<maxlogins\>' $CHROOT/etc/security/limits.d/*.conf; then
	sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" $CHROOT/etc/security/limits.d/*.conf
elif grep -q '^[^#]*\<maxlogins\>' $CHROOT/etc/security/limits.conf; then
	sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" $CHROOT/etc/security/limits.conf
else
	echo "*	hard	maxlogins	$var_accounts_max_concurrent_login_sessions" >> $CHROOT/etc/security/limits.conf
fi


) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions'

###############################################################################
# BEGIN fix (18 / 23) for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc'"); (

var_accounts_user_umask='077'

grep -q "^[^#]*\bumask" $CHROOT/etc/bashrc && \
  sed -i -E -e "s/^([^#]*\bumask)[[:space:]]+[[:digit:]]+/\1 $var_accounts_user_umask/g" $CHROOT/etc/bashrc
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> $CHROOT/etc/bashrc
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc'

###############################################################################
# BEGIN fix (19 / 23) for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_csh_cshrc'
###############################################################################
(>&2 echo "Remediating rule 19/23: 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_csh_cshrc'"); (

var_accounts_user_umask='077'


grep -q "^\s*umask" $CHROOT/etc/csh.cshrc && \
  sed -i -E -e "s/^(\s*umask).*/\1 $var_accounts_user_umask/g" $CHROOT/etc/csh.cshrc
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> $CHROOT/etc/csh.cshrc
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_csh_cshrc'

###############################################################################
# BEGIN fix (20 / 23) for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs'"); (

var_accounts_user_umask='077'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^UMASK")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_user_umask"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^UMASK\\>" "$CHROOT/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^UMASK\\>.*/$escaped_formatted_output/gi" "$CHROOT/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "$CHROOT/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$CHROOT/etc/login.defs"
    fi
    cce="CCE-83647-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$CHROOT/etc/login.defs" >> "$CHROOT/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "$CHROOT/etc/login.defs"
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs'

###############################################################################
# BEGIN fix (21 / 23) for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile'
###############################################################################
(>&2 echo "Remediating rule : 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile'"); (

var_accounts_user_umask='077'


readarray -t profile_files < <(find $CHROOT/etc/profile.d/ -type f -name '*.sh' -or -name 'sh.local')

for file in "${profile_files[@]}" $CHROOT/etc/profile; do
  grep -qE '^[^#]*umask' "$file" && sed -i -E "s/^(\s*umask\s*)[0-7]+/\1$var_accounts_user_umask/g" "$file"
done

if ! grep -qrE '^[^#]*umask' $CHROOT/etc/profile*; then
  echo "umask $var_accounts_user_umask" >> /etc/profile
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile'

###############################################################################
# BEGIN fix  for 'xccdf_org.ssgproject.content_rule_display_login_attempts'
###############################################################################
(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_display_login_attempts'"); (

# Files to ensure are correct (scanner may check any of these)
PAM_FILE="${CHROOT:-}/etc/pam.d/postlogin"

if [ -f "$PAM_FILE" ]; then
    echo "Fixing pam_lastlog in $PAM_FILE"

    # Remove all existing pam_lastlog.so lines
    sed -i -E --follow-symlinks '/pam_lastlog\.so/d' "$PAM_FILE"

    # Find where to insert the new one — after pam_succeed_if.so if present
    LAST_MATCH_LINE=$(grep -nP "^\s*session\s+.*pam_succeed_if\.so" "$PAM_FILE" | tail -n 1 | cut -d: -f1 || true)

    if [ -n "$LAST_MATCH_LINE" ]; then
        sed -i --follow-symlinks "${LAST_MATCH_LINE} a session [default=1] pam_lastlog.so showfailed" "$PAM_FILE"
    else
        echo "session [default=1] pam_lastlog.so showfailed" >> "$PAM_FILE"
    fi

    echo "Resulting pam_lastlog lines:"
    grep -n pam_lastlog.so "$PAM_FILE"
else
    echo "Warning: $PAM_FILE not found. Skipping."
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_display_login_attempts'

# ———————— Helper: run sed with proper root (handles chroot safely) ————————
run_sed() {
    sed -i -E --follow-symlinks "$@"
}

(>&2 echo "Remediating rule: 'xccdf_org.ssgproject.content_rule_display_login_attempts'"); (

# Resolve real paths
TARGET_FILE="${CHROOT:-}/etc/pam.d/postlogin"

echo "Modifying PAM file: $TARGET_FILE"

# 1. Ensure line exists: session [default=1] pam_lastlog.so
if ! grep -qP '^\s*session\s+\[default=1\]\s+pam_lastlog\.so' "$TARGET_FILE"; then
    if grep -qP '^\s*session\s+.*\s+pam_lastlog\.so' "$TARGET_FILE"; then
        # There is a pam_lastlog line, but wrong control → fix it
        run_sed "$TARGET_FILE" "s/^\(\s*session\s\+\).*pam_lastlog\.so/\1[default=1] pam_lastlog.so/"
        echo "Fixed existing pam_lastlog control to [default=1]"
    else
        # No pam_lastlog line at all → insert after last pam_succeed_if or at end
        if grep -q 'pam_succeed_if\.so' "$TARGET_FILE"; then
            last_line=$(grep -n 'pam_succeed_if\.so' "$TARGET_FILE" | tail -n1 | cut -d: -f1)
            sed -i "${last_line}a session     [default=1]     pam_lastlog.so" "$TARGET_FILE"
            echo "Inserted pam_lastlog line after pam_succeed_if"
        else
            echo "session     [default=1]     pam_lastlog.so" >> "$TARGET_FILE"
            echo "Appended pam_lastlog line"
        fi
    fi
fi

# 2. Ensure "showfailed" is present on the [default=1] line
if ! grep -qP '^\s*session\s+\[default=1\]\s+pam_lastlog\.so.*\sshowfailed\b' "$TARGET_FILE"; then
    run_sed "$TARGET_FILE" '/^\s*session\s\+\[default=1\]\s\+pam_lastlog\.so/ s/$/ showfailed/'
    echo "Added 'showfailed' option"
fi

# 3. Remove any "silent" option from the same line (STIG requirement)
if grep -qP '^\s*session\s+\[default=1\]\s+pam_lastlog\.so.*\bsilent\b' "$TARGET_FILE"; then
    run_sed "$TARGET_FILE" 's/(\s*session\s+\[default=1\]\s+pam_lastlog\.so[^\n]*)\s+\bsilent\b(\s|$)/\1\2/g'
    run_sed "$TARGET_FILE" 's/(\s*session\s+\[default=1\]\s+pam_lastlog\.so[^\n]*)\s+\bsilent=[^\s]*//g'
    echo "Removed 'silent' option"
fi

echo "Remediation complete on $TARGET_FILE"
echo "Final line:"
grep 'pam_lastlog\.so' "$TARGET_FILE" | grep '\[default=1\]'

) # END fix for 'xccdf_org.ssgproject.content_rule_display_login_attempts'


# Print completion message
echo "Completed applying all 45 DISA STIG rules for RHEL 9"
