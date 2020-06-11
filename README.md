*This guide has been shortened to be fit for Arvan users.*


This is a guide to using [YubiKey](https://www.yubico.com/products/yubikey-hardware/) as a [SmartCard](https://security.stackexchange.com/questions/38924/how-does-storing-gpg-ssh-private-keys-on-smart-cards-compare-to-plain-usb-drives) for storing GPG encryption, signing and authentication keys, which can also be used for SSH. Many of the principles in this document are applicable to other smart card devices.

Keys stored on YubiKey are non-exportable (as opposed to file-based keys that are stored on disk) and are convenient for everyday use. Instead of having to remember and enter passphrases to unlock SSH/GPG keys, YubiKey needs only a physical touch after being unlocked with a PIN code. All signing and encryption operations happen on the card, rather than in OS memory.

# Resetting your Yubikey

https://support.yubico.com/support/solutions/articles/15000006421-resetting-the-openpgp-applet-on-the-yubikey

# Creating keys

Create a temporary directory which will be cleared on [reboot](https://en.wikipedia.org/wiki/Tmpfs):

```console
$ export GNUPGHOME=$(mktemp -d)

$ cd $GNUPGHOME
```

# Master key

The first key to generate is the master key. It will be used for certification only: to issue sub-keys that are used for encryption, signing and authentication.

**Important** The master key should be kept offline at all times and only accessed to revoke or issue new sub-keys. Keys can also be generated on the YubiKey itself to ensure no other copies exist.

Do not set the master key to expire - see [Note #3](#notes).

```console
$ gpg --expert --full-generate-key

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
   (9) ECC and ECC
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (13) Existing key
Your selection? 8

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? E

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? S

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Certify

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? Q
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 0
Key does not expire at all
Is this correct? (y/N) y
```

Select a name and email address - neither has to be valid nor existing.

```console
GnuPG needs to construct a user ID to identify your key.

Real name: Dr Duh
Email address: doc@duh.to
Comment: [Optional - leave blank]
You selected this USER-ID:
    "Dr Duh <doc@duh.to>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o

We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

gpg: /tmp.FLZC0xcM/trustdb.gpg: trustdb created
gpg: key 0xFF3E7D88647EBCDB marked as ultimately trusted
gpg: directory '/tmp.FLZC0xcM/openpgp-revocs.d' created
gpg: revocation certificate stored as '/tmp.FLZC0xcM/openpgp-revocs.d/011CE16BD45B27A55BA8776DFF3E7D88647EBCDB.rev'
public and secret key created and signed.

pub   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [C]
      Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
uid                              Dr Duh <doc@duh.to>
```

Export the key ID as a [variable](https://stackoverflow.com/questions/1158091/defining-a-variable-with-or-without-export/1158231#1158231) (`KEYID`) for use later:

```console
$ export KEYID=0xFF3E7D88647EBCDB
```

# Sub-keys

Edit the master key to add sub-keys:

```console
$ gpg --expert --edit-key $KEYID

Secret key is available.

sec  rsa4096/0xEA5DE91459B80592
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
[ultimate] (1). Dr Duh <doc@duh.to>
```

Use 4096-bit key sizes.

Use a 1 year expiration for sub-keys - they can be renewed using the offline master key. See [rotating keys](#rotating-keys).

## Signing

Create a [signing key](https://stackoverflow.com/questions/5421107/can-rsa-be-both-used-as-encryption-and-signature/5432623#5432623) by selecting `(4) RSA (sign only)`:

```console
gpg> addkey
Key is protected.

You need a passphrase to unlock the secret key for
user: "Dr Duh <doc@duh.to>"
4096-bit RSA key, ID 0xFF3E7D88647EBCDB, created 2016-05-24

Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
Your selection? 4
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2018 00:00:00 PM UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
[ultimate] (1). Dr Duh <doc@duh.to>
```

## Encryption

Next, create an [encryption key](https://www.cs.cornell.edu/courses/cs5430/2015sp/notes/rsa_sign_vs_dec.php) by selecting `(6) RSA (encrypt only)`:

```console
gpg> addkey
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (12) ECC (encrypt only)
  (13) Existing key
Your selection? 6
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2018 00:00:00 PM UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09       usage: E
[ultimate] (1). Dr Duh <doc@duh.to>
```

## Authentication

Finally, create an [authentication key](https://superuser.com/questions/390265/what-is-a-gpg-with-authenticate-capability-used-for).

GPG doesn't provide an authenticate-only key type, so select `(8) RSA (set your own capabilities)` and toggle the required capabilities until the only allowed action is `Authenticate`:

```console
gpg> addkey
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (12) ECC (encrypt only)
  (13) Existing key
Your selection? 8

Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions: Sign Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? S

Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions: Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? E

Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions:

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? A

Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions: Authenticate

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? Q
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2018 00:00:00 PM UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
```

Finish by saving the keys.

```console
gpg> save
```

# Verify

List the generated secret keys and verify the output:

```console
$ gpg -K
/tmp.FLZC0xcM/pubring.kbx
-------------------------------------------------------------------------
sec   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [C]
      Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
uid                            Dr Duh <doc@duh.to>
ssb   rsa4096/0xBECFA3C1AE191D15 2017-10-09 [S] [expires: 2018-10-09]
ssb   rsa4096/0x5912A795E90DD2CF 2017-10-09 [E] [expires: 2018-10-09]
ssb   rsa4096/0x3F29127E79649A3D 2017-10-09 [A] [expires: 2018-10-09]
```

# Configure Smartcard

**Windows** Use the [YubiKey NEO Manager](https://www.yubico.com/products/services-software/download/yubikey-neo-manager/) to enable CCID functionality.

Use GPG to configure YubiKey as a smartcard:

```console
$ gpg --card-edit
Reader ...........: Yubico Yubikey 4 OTP U2F CCID
Application ID ...: D2760001240102010006055532110000
Version ..........: 2.1
Manufacturer .....: Yubico
Serial number ....: 05553211
Name of cardholder: [not set]
Language prefs ...: [not set]
Sex ..............: unspecified
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 0 3
Signature counter : 0
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
```

## Change PIN

The default PIN is `123456` and default Admin PIN (PUK) is `12345678`. CCID-mode PINs can be up to 127 ASCII characters.

The Admin PIN is required for some card operations and to unblock a PIN that has been entered incorrectly more than three times. See the GnuPG documentation on [Managing PINs](https://www.gnupg.org/howtos/card-howto/en/ch03s02.html) for details.

```console
gpg/card> admin
Admin commands are allowed

gpg/card> passwd
gpg: OpenPGP card no. D2760001240102010006055532110000 detected

1 - change PIN
2 - unblock PIN
3 - change Admin PIN
4 - set the Reset Code
Q - quit

Your selection? 3
PIN changed.

1 - change PIN
2 - unblock PIN
3 - change Admin PIN
4 - set the Reset Code
Q - quit

Your selection? 1
PIN changed.

1 - change PIN
2 - unblock PIN
3 - change Admin PIN
4 - set the Reset Code
Q - quit

Your selection? q
```

## Set information

Some fields are optional.

```console
gpg/card> name
Cardholder's surname: Duh
Cardholder's given name: Dr

gpg/card> lang
Language preferences: en

gpg/card> login
Login data (account name): doc@duh.to

gpg/card> list

Application ID ...: D2760001240102010006055532110000
Version ..........: 2.1
Manufacturer .....: unknown
Serial number ....: 05553211
Name of cardholder: Dr Duh
Language prefs ...: en
Sex ..............: unspecified
URL of public key : [not set]
Login data .......: doc@duh.to
Private DO 4 .....: [not set]
Signature PIN ....: not forced
Key attributes ...: 2048R 2048R 2048R
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 0 3
Signature counter : 0
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]

gpg/card> quit
```

# Transfer keys

**Important** Transferring keys to YubiKey using `keytocard` is a destructive, one-way operation only. Make sure you've made a backup before proceeding: `keytocard` converts the local, on-disk key into a stub, which means the on-disk copy is no longer usable to transfer to subsequent security key devices or mint additional keys.

Previous GPG versions required the `toggle` command before selecting keys. The currently selected key(s) are indicated with an `*`. When moving keys only one key should be selected at a time.

```console
$ gpg --edit-key $KEYID

Secret key is available.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09  usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09  usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09  usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
```

## Signing

Select and move the signature key. You will be prompted for the key passphrase and Admin PIN.

```console
gpg> key 1

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb* rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09  usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09  usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09  usage: A
[ultimate] (1). Dr Duh <doc@duh.to>

gpg> keytocard
Please select where to store the key:
   (1) Signature key
   (3) Authentication key
Your selection? 1

You need a passphrase to unlock the secret key for
user: "Dr Duh <doc@duh.to>"
4096-bit RSA key, ID 0xBECFA3C1AE191D15, created 2016-05-24
```

## Encryption

Type `key 1` again to de-select and `key 2` to select the next key:

```console
gpg> key 1

gpg> key 2

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09  usage: S
ssb* rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09  usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09  usage: A
[ultimate] (1). Dr Duh <doc@duh.to>

gpg> keytocard
Please select where to store the key:
   (2) Encryption key
Your selection? 2

[...]
```

## Authentication

Type `key 2` again to deselect and `key 3` to select the last key:

```console
gpg> key 2

gpg> key 3

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09  usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09  usage: E
ssb* rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09  usage: A
[ultimate] (1). Dr Duh <doc@duh.to>

gpg> keytocard
Please select where to store the key:
   (3) Authentication key
Your selection? 3

gpg> save
```

# Verify card

Verify the sub-keys have been moved to YubiKey as indicated by `ssb>`:

```console
$ gpg -K
/tmp.FLZC0xcM/pubring.kbx
-------------------------------------------------------------------------
sec   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [C]
      Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
uid                            Dr Duh <doc@duh.to>
ssb>  rsa4096/0xBECFA3C1AE191D15 2017-10-09 [S] [expires: 2018-10-09]
ssb>  rsa4096/0x5912A795E90DD2CF 2017-10-09 [E] [expires: 2018-10-09]
ssb>  rsa4096/0x3F29127E79649A3D 2017-10-09 [A] [expires: 2018-10-09]
```

# SSH

[gpg-agent](https://wiki.archlinux.org/index.php/GnuPG#SSH_agent) supports the OpenSSH ssh-agent protocol (`enable-ssh-support`), as well as Putty's Pageant on Windows (`enable-putty-support`). This means it can be used instead of the traditional ssh-agent / pageant. There are some differences from ssh-agent, notably that gpg-agent does not _cache_ keys rather it converts, encrypts and stores them - persistently - as GPG keys and then makes them available to ssh clients. Any existing ssh private keys that you'd like to keep in `gpg-agent` should be deleted after they've been imported to the GPG agent.

When importing the key to `gpg-agent`, you'll be prompted for a passphrase to protect that key within GPG's key store - you may want to use the same passphrase as the original's ssh version. GPG can both cache passphrases for a determined period (ref. `gpg-agent`'s various `cache-ttl` options), and since version 2.1 can store and fetch passphrases via the macOS keychain. Note than when removing the old private key after importing to `gpg-agent`, keep the `.pub` key file around for use in specifying ssh identities (e.g. `ssh -i /path/to/identity.pub`).

Probably the biggest thing missing from `gpg-agent`'s ssh agent support is being able to remove keys. `ssh-add -d/-D` have no effect. Instead, you need to use the `gpg-connect-agent` utility to lookup a key's keygrip, match that with the desired ssh key fingerprint (as an MD5) and then delete that keygrip. The [gnupg-users mailing list](https://lists.gnupg.org/pipermail/gnupg-users/2016-August/056499.html) has more information.

## Create configuration

Create a hardened configuration for gpg-agent by downloading [drduh/config/gpg-agent.conf](https://github.com/drduh/config/blob/master/gpg-agent.conf):

```console
$ cd ~/.gnupg

$ wget https://raw.githubusercontent.com/drduh/config/master/gpg-agent.conf

$ grep -ve "^#" gpg-agent.conf
enable-ssh-support
default-cache-ttl 60
max-cache-ttl 120
pinentry-program /usr/bin/pinentry-curses
```

**Tip** Set `pinentry-program /usr/bin/pinentry-gnome3` for a GUI-based prompt.

On macOS, use `brew install pinentry-mac` and adjust the program path to suit.

uncomment this line:
```
pinentry-program /usr/local/bin/pinentry-mac
```

## Replace agents

To launch `gpg-agent` for use by SSH, use the `gpg-connect-agent /bye` or `gpgconf --launch gpg-agent` commands.

Add these to the shell `rc` file:

```console
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"
gpg-connect-agent updatestartuptty /bye
```

On some systems, you may need to use the following instead:

```console
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent
```

## Copy public key

**Note** It is *not* necessary to import the corresponding GPG public key in order to use SSH.

Copy and paste the output from `ssh-add` to the server's `authorized_keys` file:

```console
$ ssh-add -L
ssh-rsa AAAAB4NzaC1yc2EAAAADAQABAAACAz[...]zreOKM+HwpkHzcy9DQcVG2Nw== cardno:000605553211
```

## (Optional) Save public key for identity file configuration

By default, SSH attempts to use all the identities available via the agent. It's often a good idea to manage exactly which keys SSH will use to connect to a server, for example to separate different roles or [to avoid being fingerprinted by untrusted ssh servers](https://blog.filippo.io/ssh-whoami-filippo-io/). To do this you'll need to use the command line argument `-i [identity_file]` or the `IdentityFile` and `IdentitiesOnly` options in `.ssh/config`.

The argument provided to `IdentityFile` is traditionally the path to the _private_ key file (for example `IdentityFile ~/.ssh/id_rsa`). For the YubiKey - indeed, in general for keys stored in an ssh agent - `IdentityFile` should point to the _public_ key file, `ssh` will select the appropriate private key from those available via the ssh agent. To prevent `ssh` from trying all keys in the agent use the `IdentitiesOnly yes` option along with one or more `-i` or `IdentityFile` options for the target host.

To reiterate, with `IdentitiesOnly yes`, `ssh` will not automatically enumerate public keys loaded into `ssh-agent` or `gpg-agent`. This means `publickey` authentication will not proceed unless explicitly named by `ssh -i [identity_file]` or in `.ssh/config` on a per-host basis.

In the case of YubiKey usage, to extract the public key from the ssh agent:

```console
$ ssh-add -L | grep "cardno:000605553211" > ~/.ssh/id_rsa_yubikey.pub
```

Then you can explicitly associate this YubiKey-stored key for used with a host, `github.com` for example, as follows:

```console
$ cat << EOF >> ~/.ssh/config
Host github.com
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_rsa_yubikey.pub
EOF
```

## Connect with public key authentication

```console
$ ssh git@github.com -vvv
[...]
debug2: key: cardno:000605553211 (0x1234567890),
debug1: Authentications that can continue: publickey
debug3: start over, passed a different list publickey
debug3: preferred gssapi-keyex,gssapi-with-mic,publickey,keyboard-interactive,password
debug3: authmethod_lookup publickey
debug3: remaining preferred: keyboard-interactive,password
debug3: authmethod_is_enabled publickey
debug1: Next authentication method: publickey
debug1: Offering RSA public key: cardno:000605553211
debug3: send_pubkey_test
debug2: we sent a publickey packet, wait for reply
debug1: Server accepts key: pkalg ssh-rsa blen 535
debug2: input_userauth_pk_ok: fp e5:de:a5:74:b1:3e:96:9b:85:46:e7:28:53:b4:82:c3
debug3: sign_and_send_pubkey: RSA e5:de:a5:74:b1:3e:96:9b:85:46:e7:28:53:b4:82:c3
debug1: Authentication succeeded (publickey).
[...]
```

**Note** To make multiple connections or securely transfer many files, consider using the [ControlMaster](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing) ssh option. Also see [drduh/config/ssh_config](https://github.com/drduh/config/blob/master/ssh_config).

## Import SSH keys

If there are existing SSH keys that you wish to make available via `gpg-agent`, you'll need to import them. You should then remove the original private keys. When importing the key, `gpg-agent` uses the key's filename as the key's label; this makes it easier to follow where the key originated from. In this example, we're starting with just the YubiKey's key in place and importing `~/.ssh/id_rsa`:

```console
$ ssh-add -l
4096 SHA256:... cardno:00060123456 (RSA)

$ ssh-add ~/.ssh/id_rsa && rm ~/.ssh/id_rsa
```

When invoking `ssh-add`, it will prompt for the SSH key's passphrase if present, then the `pinentry` program will prompt and confirm for a new passphrase to use to encrypt the converted key within the GPG key store.

The migrated key should be listed in `ssh-add -l`:

```console
$ ssh-add -l
4096 SHA256:... cardno:00060123456 (RSA)
2048 SHA256:... /Users/username/.ssh/id_rsa (RSA)
```

Or to show the keys with MD5 fingerprints, as used by `gpg-connect-agent`'s `KEYINFO` and `DELETE_KEY` commands:

```console
$ ssh-add -E md5 -l
4096 MD5:... cardno:00060123456 (RSA)
2048 MD5:... /Users/username/.ssh/id_rsa (RSA)
```

When using the key `pinentry` will be invoked to request the key's passphrase. The passphrase will be cached for up to 10 minutes idle time between uses, to a maximum of 2 hours.


## GitHub

You can use YubiKey to sign GitHub commits and tags. It can also be used for GitHub SSH authentication, allowing you to push, pull, and commit without a password.

Login to GitHub and upload SSH and PGP public keys in Settings.

To configure a signing key:

	> git config --global user.signingkey $KEYID

Make sure the user.email option matches the email address associated with the PGP identity.

Now, to sign commits or tags simply use the `-S` option. GPG will automatically query YubiKey and prompt you for a PIN.

To authenticate:

#### Prerequisites

* Ubuntu 16.04 or newer for WSL
* Kleopatra
* [Windows configuration](#windows)


# Reset

If PIN attempts are exceeded, the card is locked and must be [reset](https://developers.yubico.com/ykneo-openpgp/ResetApplet.html) and set up again using the encrypted backup.

Copy the following script to a file and run `gpg-connect-agent -R $file` to lock and terminate the card. Then re-insert YubiKey to reset.

```console
/hex
scd serialno
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 e6 00 00
scd apdu 00 44 00 00
/echo Card has been successfully reset.
```

# Notes

1. YubiKey has two configurations: one invoked with a short press, and the other with a long press. By default, the short-press mode is configured for HID OTP - a brief touch will emit an OTP string starting with `cccccccc`. If you rarely use the OTP mode, you can swap it to the second configuration via the YubiKey Personalization tool. If you *never* use OTP, you can disable it entirely using the [YubiKey Manager](https://developers.yubico.com/yubikey-manager) application (note, this not the similarly named YubiKey NEO Manager).
1. Programming YubiKey for GPG keys still lets you use its other configurations - [U2F](https://en.wikipedia.org/wiki/Universal_2nd_Factor), [OTP](https://www.yubico.com/faq/what-is-a-one-time-password-otp/) and [static password](https://www.yubico.com/products/services-software/personalization-tools/static-password/) modes, for example.
1. Setting an expiry essentially forces you to manage your subkeys and announces to the rest of the world that you are doing so. Setting an expiry on a primary key is ineffective for protecting the key from loss - whoever has the primary key can simply extend its expiry period. Revocation certificates are [better suited](https://security.stackexchange.com/questions/14718/does-openpgp-key-expiration-add-to-security/79386#79386) for this purpose. It may be appropriate for your use case to set expiry dates on subkeys.
1. To switch between two or more identities on different keys - unplug the first key and restart gpg-agent, ssh-agent and pinentry with `pkill gpg-agent ; pkill ssh-agent ; pkill pinentry ; eval $(gpg-agent --daemon --enable-ssh-support)`, then plug in the other key and run `gpg-connect-agent updatestartuptty /bye` - then it should be ready for use.

# Troubleshooting

- Use `man gpg` to understand GPG options and command-line flags.

- If you encounter problems connecting to YubiKey with GPG - try unplugging and re-inserting YubiKey, and restarting the `gpg-agent` process.

- If you receive the error, `gpg: decryption failed: secret key not available` - you likely need to install GnuPG version 2.x.

- If you receive the error, `Yubikey core error: no yubikey present` - make sure the YubiKey is inserted correctly. It should blink once when plugged in.

- If you still receive the error, `Yubikey core error: no yubikey present` - you likely need to install newer versions of yubikey-personalize as outlined in [Required software](#required-software).

- If you receive the error, `Yubikey core error: write error` - YubiKey is likely locked. Install and run yubikey-personalization-gui to unlock it.

- If you receive the error, `Key does not match the card's capability` - you likely need to use 2048 bit RSA key sizes.

- If you receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - make sure you replaced `ssh-agent` with `gpg-agent` as noted above.

- If you still receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - [run the command](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=835394) `gpg-connect-agent updatestartuptty /bye`

- If you still receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - check `~/.gnupg/gpg-agent.conf` to make sure the path to `pinentry` is correct.

- If you receive the error, `Error connecting to agent: No such file or directory` from `ssh-add -L`, the UNIX file socket that the agent uses for communication with other processes may not be set up correctly. On Debian, try `export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"`. Also see that `gpgconf --list-dirs agent-ssh-socket` is returning single path, to existing `S.gpg-agent.ssh` socket.

- If you receive the error, `Permission denied (publickey)`, increase ssh verbosity with the `-v` flag and ensure the public key from the card is being offered: `Offering public key: RSA SHA256:abcdefg... cardno:00060123456`. If it is, ensure you are connecting as the right user on the target system, rather than as the user on the local system. Otherwise, be sure `IdentitiesOnly` is not [enabled](https://github.com/FiloSottile/whosthere#how-do-i-stop-it) for this host.

- If SSH authentication stil fails - add up to 3 `-v` flags to increase verbosity.

# Links

* https://alexcabal.com/creating-the-perfect-gpg-keypair/
* https://blog.habets.se/2013/02/GPG-and-SSH-with-Yubikey-NEO
* https://blog.josefsson.org/2014/06/23/offline-gnupg-master-key-and-subkeys-on-yubikey-neo-smartcard/
* https://blog.onefellow.com/post/180065697833/yubikey-forwarding-ssh-keys
* https://developers.yubico.com/PGP/Card_edit.html
* https://developers.yubico.com/PIV/Introduction/Admin_access.html
* https://developers.yubico.com/yubico-piv-tool/YubiKey_PIV_introduction.html
* https://developers.yubico.com/yubikey-personalization/
* https://developers.yubico.com/yubikey-piv-manager/PIN_and_Management_Key.html
* https://evilmartians.com/chronicles/stick-with-security-yubikey-ssh-gnupg-macos
* https://gist.github.com/ageis/14adc308087859e199912b4c79c4aaa4
* https://github.com/herlo/ssh-gpg-smartcard-config
* https://github.com/tomlowenthal/documentation/blob/master/gpg/smartcard-keygen.md
* https://help.riseup.net/en/security/message-security/openpgp/best-practices
* https://jclement.ca/articles/2015/gpg-smartcard/
* https://rnorth.org/gpg-and-ssh-with-yubikey-for-mac
* https://trmm.net/Yubikey
* https://www.bootc.net/archives/2013/06/09/my-perfect-gnupg-ssh-agent-setup/
* https://www.esev.com/blog/post/2015-01-pgp-ssh-key-on-yubikey-neo/
* https://www.hanselman.com/blog/HowToSetupSignedGitCommitsWithAYubiKeyNEOAndGPGAndKeybaseOnWindows.aspx
* https://www.void.gr/kargig/blog/2013/12/02/creating-a-new-gpg-key-with-subkeys/
* https://mlohr.com/gpg-agent-forwarding/
