#ifndef __KSU_H_KSU
#define __KSU_H_KSU

#define KERNEL_SU_VERSION KSU_VERSION

struct cred* ksu_cred;

#if defined(CONFIG_KSU_DEBUG) || defined(CONFIG_KSU_SHELL_HAS_SU_ALWAYS)
static bool allow_shell = true;
#else
static bool allow_shell = false;
#endif

static inline int startswith(char *s, char *prefix)
{
	return strncmp(s, prefix, strlen(prefix));
}

static inline int endswith(const char *s, const char *t)
{
	size_t slen = strlen(s);
	size_t tlen = strlen(t);
	if (tlen > slen)
		return 1;
	return strcmp(s + slen - tlen, t);
}

extern struct cred* ksu_cred;

#ifdef CONFIG_KSU_SUSFS
// Backup of the live SELinux policy snapshotted before KSU injects its own
// rules. Populated in kernel/selinux/rules.c::apply_kernelsu_rules() and
// consumed by the susfs SELinux-hide data provider (feature/selinux_hide.c)
// and by the host kernel's selinuxfs.c/hooks.c susfs hooks (via fake_state).
extern struct selinux_policy *backup_sepolicy;
// Defined in kernel/feature/selinux_hide.c; called from apply_kernelsu_rules()
// once backup_sepolicy is captured, to arm the susfs context/AVC spoofing.
void ksu_selinux_hide_susfs_set_running(bool on);
#endif

#endif
