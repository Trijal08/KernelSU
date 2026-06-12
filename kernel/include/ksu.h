#ifndef __KSU_H_KSU
#define __KSU_H_KSU

#define KERNEL_SU_VERSION KSU_VERSION

#define EVENT_POST_FS_DATA 1
#define EVENT_BOOT_COMPLETED 2
#define EVENT_MODULE_MOUNTED 3

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
#endif

#endif
