/**
 *  NOTE: this isnt the fullblown thing like upstream's where we straight up backport
 *  SELinux. This is just questionable to do when we want to support a plethora of
 *  non-standard kernels.
 *
 *  While what we are doing here is kinda improper, for most cases
 *  this should be mroe than enough.
 *
 *  this will include write_op / selinux_transaction_write spoofing and then avc spoofing.
 *  our goal for this one is to be self contained as much as possible
 *  with only one call from ksu's initcall.
 *
 */

// enabled by default
// NOTE: non-static so the host kernel's susfs selinux hooks (security/selinux/
// selinuxfs.c, hooks.c from 50_add_susfs...) can reach it via `extern`.
bool ksu_selinux_hide_enabled __read_mostly = true;

#ifdef CONFIG_KSU_SUSFS
// ===========================================================================
// susfs full SELinux-hide data provider
// ---------------------------------------------------------------------------
// The host kernel patch (50_add_susfs_in_gki...) implements the actual spoofing
// of /sys/fs/selinux/{context,access,status} and the setprocattr LSM hook, but
// references the backing state from KSU as `extern`. We define it all here.
//
//   - ksu_selinux_hide_running : gates context/access/setprocattr spoofing;
//                                armed once a valid backup_sepolicy exists.
//   - fake_state               : wraps backup_sepolicy so the kernel's stock
//                                security_context_to_sid(&fake_state, ...) etc.
//                                resolve against the pristine (pre-KSU) policy.
//   - fake_status / key        : frozen SELinux status page served to app uids
//                                so a policy reload doesn't perturb what they see.
// ===========================================================================
bool ksu_selinux_hide_running __read_mostly = false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
int security_context_to_sid_with_policy(struct selinux_policy *policy, const char *scontext, u32 scontext_len,
                                        u32 *sid, u32 def_sid, gfp_t gfp_flags);
int security_sid_to_context_with_policy(struct selinux_policy *policy, u32 sid, char **scontext, u32 *scontext_len);
void security_compute_av_user_with_policy(struct selinux_policy *policy, u32 ssid, u32 tsid, u16 tclass,
                                          struct av_decision *avd);
extern void security_dump_masked_av_fn(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                       u16 tclass, u32 permissions, const char *reason);
extern void context_struct_compute_av_fn(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                         u16 tclass, struct av_decision *avd, struct extended_perms *xperms);
#else
struct selinux_state fake_state;
#endif

DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);
struct page *fake_status = NULL;

void initialize_fake_status(void)
{
	mutex_lock(&selinux_state.status_lock);
	if (fake_status)
		goto out;
	if (!selinux_state.status_page) {
		pr_warn("initialize_fake_status: status_page not exist\n");
		goto out;
	}

	struct selinux_kernel_status *status = page_address(selinux_state.status_page);
	if (!status->enforcing) {
		pr_warn("initialize_fake_status: skip not enforcing\n");
		goto out;
	}

	struct page *new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!new_page) {
		pr_err("initialize_fake_status: failed to allocate page\n");
		goto out;
	}

	struct selinux_kernel_status *new_status = page_address(new_page);
	memcpy(new_status, status, sizeof(*status));

	fake_status = new_page;
	pr_info("initialize_fake_status initialized: sequence=%d, policyload=%d, enforcing=%d\n", new_status->sequence,
		new_status->policyload, new_status->enforcing);

out:
	mutex_unlock(&selinux_state.status_lock);
}

void ksu_selinux_hide_handle_second_stage(void)
{
	initialize_fake_status();
	if (fake_status)
		static_key_disable(&fake_status_initialize_key.key);
	else
		pr_warn("selinux_hide: fake status need late initialization\n");
}

void ksu_selinux_hide_handle_post_fs_data(void)
{
	static_key_disable(&fake_status_initialize_key.key);
	if (!fake_status)
		pr_err("selinux_hide: fake status is not initialized after post-fs-data!\n");
}
#endif // CONFIG_KSU_SUSFS

// sids for avc spoofing
static u32 ksu_sid __read_mostly = 0;
static u32 priv_app_sid __read_mostly = 0;

static inline int ksu_selinux_get_sids()
{
	int err;

	err = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid);
	if (!err)
		pr_info("selinux_hide: ksu_sid: %u\n", ksu_sid);

	err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (!err)
		pr_info("selinux_hide: priv_app_sid: %u\n", priv_app_sid);

	if (!ksu_sid || !priv_app_sid)
		return -1;

	return 0;
}

void ksu_slow_avc_audit(u32 *tsid)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return;

	if (*tsid != ksu_sid)
		return;

	pr_info("selinux_hide: slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
	*tsid = priv_app_sid;

	return;
}

static inline bool ksu_should_destroy_context(char *str)
{
	if (!str)
		return false;

	bool status = false;

	mutex_lock(&selinux_hide_list_mutex);

	size_t offset = 0;
	while (offset < ksu_hide_type_len) {
		const char *current_entry = ksu_hide_type_list + offset;
		
		if (strstr(str, current_entry)) {
			status = true;
			goto out_unlock;
		}

		offset = offset + strlen(current_entry) + 1;
	}

	// double strstr
	char *str2 = strchr(str, ' ');
	if (!str2)
		goto out_unlock;

	offset = 0;
	while (offset < ksu_hide_rule_len) {
		const char *src_rule = ksu_hide_rule_list + offset;
		size_t src_sz = strlen(src_rule) + 1;
			
		const char *tgt_rule = src_rule + src_sz;
		size_t tgt_sz = strlen(tgt_rule) + 1;

		if (strstr(str, src_rule) && strstr(str2, tgt_rule)) {
			status = true;
			goto out_unlock;
		}

		offset = offset + src_sz + tgt_sz;
	}

out_unlock:
	mutex_unlock(&selinux_hide_list_mutex);
	return status;

}

#if 0
static inline bool ksu_should_destroy_context(char *str)
{
	if (!str)
		return false;

	down_read(&ksu_sepolicy_shitlist_lock);

	struct ksu_type_node *t_node;
	list_for_each_entry(t_node, &ksu_hide_type_list, list) {
		if (strstr(str, t_node->padded_name)) {
			up_read(&ksu_sepolicy_shitlist_lock);
			return true;
		}
	}

	// double strstr
	char *str2 = strchr(str, ' ');
	if (!str2) {
		up_read(&ksu_sepolicy_shitlist_lock);
		return false;
	}		

	struct ksu_rule_node *r_node;
	list_for_each_entry(r_node, &ksu_hide_rule_list, list) {
		if (strstr(str, r_node->src) && strstr(str2, r_node->tgt)) {
			up_read(&ksu_sepolicy_shitlist_lock);
			return true;
		}
	}

	up_read(&ksu_sepolicy_shitlist_lock);
	return false;
}
#endif

// NOTE: this is also available as manual hook for 6.8+
int ksu_hide_setprocattr(const char *name, void *value, size_t size)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return 0;

	// only hook when seccomp is enabled
	if (!test_thread_flag(TIF_SECCOMP))
		return 0;

	// only appuid
	if (current_uid().val < 10000)
		return 0;

	if (!size)
		return 0;

	if (!name)
		return 0;

	if (!!strcmp(name, "current"))
		return 0;

	char *str = (char *)value;

	if (!str)
		return 0;

	// to make sure its terminated
	char buf[64] = { 0 };
	size_t len = (size < 63) ? size : 63;

	memcpy(buf, str, len);

	if (!ksu_should_destroy_context(buf))
		return 0;
	
	pr_info("selinux_hide: setprocattr: destroy: %s\n", buf);
	str[1] = '1';

	return 0;
}

// for manual hook, remove this in a month
void ksu_sel_write_context(struct file **file, char **buf, size_t *size)
{
	return;
}

#if defined(CONFIG_KPROBES)

#include <linux/kprobes.h>
static struct kprobe *slow_avc_audit_kp;

static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
#endif

	ksu_slow_avc_audit(tsid);

	return 0;
}

// copied from upstream
static struct kprobe *init_kprobe(const char *name, kprobe_pre_handler_t handler)
{
	struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
	if (!kp)
		return NULL;
	kp->symbol_name = name;
	kp->pre_handler = handler;

	int ret = register_kprobe(kp);
	pr_info("%s: register %s kprobe: %d\n", __func__, name, ret);
	if (ret) {
		kfree(kp);
		return NULL;
	}

	return kp;
}
static void destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;
	if (!kp)
		return;
	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}
#endif // CONFIG_KPROBES


static void ksu_selinux_hide_enable() 
{
	int ret = ksu_selinux_get_sids();
	if (ret)
		pr_info("selinux_hide: sid grab fail?\n");

#if defined(CONFIG_KPROBES)
	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
#endif

	ksu_selinux_hide_enabled = true;

#ifdef CONFIG_KSU_SUSFS
	// Arm the susfs host-side spoofing: point fake_state at the pristine backup
	// policy and set the running flag so the host kernel's my_write_context /
	// my_write_access / my_setprocattr start canonicalizing against it.
	if (backup_sepolicy) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
		fake_state.initialized = true;
		fake_state.policy = backup_sepolicy;
#endif
		ksu_selinux_hide_running = true;
		pr_info("selinux_hide: susfs spoofing armed (backup_sepolicy=%p)\n", backup_sepolicy);
	} else {
		pr_err("selinux_hide: no backup_sepolicy yet; susfs context/avc spoof inactive\n");
	}
#endif // CONFIG_KSU_SUSFS
}

static void ksu_selinux_hide_disable()
{
#if defined(CONFIG_KPROBES)
	pr_info("selinux_hide: unregister slow_avc_audit kprobe!\n");
	destroy_kprobe(&slow_avc_audit_kp);
#endif

	pr_info("selinux_hide: closing down hooks!\n");

#ifdef CONFIG_KSU_SUSFS
	ksu_selinux_hide_running = false;
#endif
	ksu_selinux_hide_enabled = false;
}

// selinux_transaction_write hijack

static ssize_t (*selinux_transaction_write_fn)(struct file *file, const char __user *buf, size_t size, loff_t *pos) __read_mostly = NULL;
static __nocfi ssize_t ksu_selinux_transaction_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		goto skip_destroy;

	if (!test_thread_flag(TIF_SECCOMP))
		goto skip_destroy;

	if (current_uid().val < 10000)
		goto skip_destroy;

	char kbuf[128] = { 0 };
	if (ksu_copy_from_user_retry(kbuf, buf, 127))
		goto skip_destroy;

	if (!ksu_should_destroy_context(kbuf))
		goto skip_destroy;

	// or copy_to_user? is it writable? or we vm_mmap? or hunt for writable section on start_stack again?
	// NOTE: if this is 'timeable', to equalize, we should call selinux_transaction_write_fn before ret EINVAL
	pr_info("selinux_hide: selinux_transaction_write: destroy: %s \n", kbuf);
	return -EINVAL;

skip_destroy:
	return selinux_transaction_write_fn(file, buf, size, pos);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
extern struct selinux_state selinux_state;
#define ksu_selinux_kernel_status_page() selinux_kernel_status_page(&selinux_state)
#else
#define ksu_selinux_kernel_status_page() selinux_kernel_status_page()
#endif

static struct page *ksu_fake_status_page __read_mostly = NULL;

static int ksu_prepare_fake_status_page()
{
	struct page *real_page = ksu_selinux_kernel_status_page();
	if (!real_page)
		return -ENOMEM;

	// this is the page we present
	struct page *new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!new_page)
		return -ENOMEM;

	// we will leak one page but thats fine
	// not a leak when it is used forever :)
	struct selinux_kernel_status *real_status = page_address(real_page);
	// renamed from 'fake_status' to avoid shadowing the global susfs
	// `struct page *fake_status` added above.
	struct selinux_kernel_status *fake_kstatus = page_address(new_page);

	memcpy(fake_kstatus, real_status, sizeof(*real_status));

	fake_kstatus->enforcing = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	fake_kstatus->sequence = 4;
	fake_kstatus->policyload = 1;
#else
	fake_kstatus->sequence = 0;
	fake_kstatus->policyload = 0;
#endif

	ksu_fake_status_page = new_page;

	pr_info("selinux_hide: ksu_fake_status_page ready! seq=%d\n", fake_kstatus->sequence);
            
	return 0;
}

static int (*sel_open_handle_status_fn)(struct inode *inode, struct file *filp) __read_mostly = NULL;
static __nocfi int ksu_sel_open_handle_status(struct inode *inode, struct file *filp)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		goto orig_page;

	if (!test_thread_flag(TIF_SECCOMP))
		goto orig_page;

	if (current_uid().val < 10000)
		goto orig_page;

	// won't happen! we check this on hook init!
	// if (unlikely(!ksu_fake_status_page))
	//	goto orig_page;

	filp->private_data = ksu_fake_status_page;

	pr_info("selinux_hide: sel_open_handle_status: served fake_page\n");
	return 0;

orig_page:
	return sel_open_handle_status_fn(inode, filp);
}

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

static void ksu_init_hook_selinux_transaction_write()
{
	struct path path;
	const char *selinux_context = "/sys/fs/selinux/context";

	int error = kern_path(selinux_context, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_info("selinux_hide: kern_path err: %d\n", error);
		return;
	}

	pr_info("selinux_hide: kern_path %s ok!\n", selinux_context);

	if (!path.dentry)
		goto bail_out;

	if (!d_inode(path.dentry))
		goto bail_out;		

	struct file_operations *fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
	if (!fops)
		goto bail_out;

	if (!fops->write)
		goto bail_out;

	pr_info("selinux_hide: found transaction_ops->write at 0x%lx \n", (uintptr_t)fops->write);
	selinux_transaction_write_fn = fops->write;

	unsigned long addr = (unsigned long)&fops->write;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		goto bail_out;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		goto bail_out;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);
				
	preempt_disable();
	local_irq_disable();
					
	FORCE_VOLATILE(*target_slot) = (void *)ksu_selinux_transaction_write;
					
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();

	pr_info("selinux_hide: transaction_ops->write hijacked!\n");

bail_out:
	path_put(&path);
}

static void ksu_init_hook_selinux_status_open()
{
	struct path path;
	const char *selinux_status = "/sys/fs/selinux/status";

	int error = kern_path(selinux_status, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_info("selinux_hide: kern_path err: %d\n", error);
		return;
	}
	
	pr_info("selinux_hide: kern_path %s ok!\n", selinux_status);

	if (!path.dentry)
		goto bail_out;

	if (!d_inode(path.dentry))
		goto bail_out;	

	struct file_operations *fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
	if (!fops)
		goto bail_out;

	if (!fops->open)
		goto bail_out;

	pr_info("selinux_hide: found sel_handle_status_ops->open at 0x%lx\n", (uintptr_t)fops->open);

	sel_open_handle_status_fn = fops->open;

	unsigned long addr = (unsigned long)&fops->open;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		goto bail_out;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		goto bail_out;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);
				
	preempt_disable();
	local_irq_disable();
					
	FORCE_VOLATILE(*target_slot) = (void *)ksu_sel_open_handle_status;
					
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();

	pr_info("selinux_hide: sel_handle_status_ops->open hijacked!\n");

bail_out:
	path_put(&path);
}

// init kthread
static int ksu_hide_init_thread(void *data)
{
	set_user_nice(current, 19); // low prio

wait_start:
	// in input hook got turned off means we have ksud!
	if (!*(volatile bool *)&ksu_input_hook)
		goto init_hooks;

	msleep(5000);

	goto wait_start;

init_hooks:
	;
	// apply_kernelsu_rules_fn
	const char *ksu_domain_args[] = { KERNEL_SU_DOMAIN, NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, ksu_domain_args);

	const char *ksu_file_args[] = { KERNEL_SU_FILE, NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, ksu_file_args);

	const char *init_adb_args[] = { "init", "adb_data_file", NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_NORMAL_PERM, init_adb_args);

	// we move this to a module instead
	// const char *adbroot_args[] = { "adbroot", NULL };
	// ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, adbroot_args);

	ksu_selinux_hide_enable();
	ksu_init_hook_selinux_transaction_write();

	int tries = 0;
try_again:
	if (!ksu_prepare_fake_status_page())
		goto page_ok;
		
	msleep(1000);
	tries = tries + 1;
	if (tries > 10)
		return 0;

	goto try_again;

page_ok:
	ksu_init_hook_selinux_status_open();

	return 0;
}

static int selinux_hide_feature_get(u64 *value)
{
	*value = ksu_selinux_hide_enabled ? 1 : 0;
	return 0;
}

static int selinux_hide_feature_set(u64 value)
{
	bool enable = value != 0;
	int ret = 0;

	if (enable == ksu_selinux_hide_enabled)
		return 0;

	pr_info("selinux_hide: set to %d\n", enable);

	if (enable)
		ksu_selinux_hide_enable();
	else
		ksu_selinux_hide_disable();

	return ret;
}

static const struct ksu_feature_handler selinux_hide_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE,
	.name = "selinux_hide",
	.get_handler = selinux_hide_feature_get,
	.set_handler = selinux_hide_feature_set,
};

void __init ksu_selinux_hide_init()
{
	// we init this on a kthread
	kthread_run(ksu_hide_init_thread, NULL, "kthread");

	if (ksu_register_feature_handler(&selinux_hide_handler)) {
		pr_err("Failed to register selinux_hide feature handler\n");
	}

#ifdef CONFIG_KSU_SUSFS
	// Arm lazy init of the susfs fake SELinux status page: the host kernel's
	// my_sel_open_handle_status() calls initialize_fake_status() on the first
	// /sys/fs/selinux/status open while this key is enabled, then disables it.
	static_key_enable(&fake_status_initialize_key.key);
#endif // CONFIG_KSU_SUSFS
}

void __exit ksu_selinux_hide_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);

#ifdef CONFIG_KSU_SUSFS
	mutex_lock(&selinux_state.status_lock);
	if (fake_status)
		__free_page(fake_status);
	fake_status = NULL;
	mutex_unlock(&selinux_state.status_lock);
#endif // CONFIG_KSU_SUSFS
}


// ===========================================================================
// Canonical susfs policy-resolution helpers for kernels >= 6.6 (verbatim from
// 10_enable_susfs_for_ksu.patch). Compiled out on < 6.6 (e.g. android14-6.1),
// where the host uses the kernel stock security_*(&fake_state, ...) instead.
// ===========================================================================
#ifdef CONFIG_KSU_SUSFS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
/*
 * Caveat:  Mutates scontext.
 */
static int string_to_context_struct(struct policydb *pol, struct sidtab *sidtabp, char *scontext, struct context *ctx,
                                    u32 def_sid)
{
    struct role_datum *role;
    struct type_datum *typdatum;
    struct user_datum *usrdatum;
    char *scontextp, *p, oldc;
    int rc = 0;

    context_init(ctx);

    /* Parse the security context. */

    rc = -EINVAL;
    scontextp = scontext;

    /* Extract the user. */
    p = scontextp;
    while (*p && *p != ':')
        p++;

    if (*p == 0)
        goto out;

    *p++ = 0;

    usrdatum = symtab_search(&pol->p_users, scontextp);
    if (!usrdatum)
        goto out;

    ctx->user = usrdatum->value;

    /* Extract role. */
    scontextp = p;
    while (*p && *p != ':')
        p++;

    if (*p == 0)
        goto out;

    *p++ = 0;

    role = symtab_search(&pol->p_roles, scontextp);
    if (!role)
        goto out;
    ctx->role = role->value;

    /* Extract type. */
    scontextp = p;
    while (*p && *p != ':')
        p++;
    oldc = *p;
    *p++ = 0;

    typdatum = symtab_search(&pol->p_types, scontextp);
    if (!typdatum || typdatum->attribute)
        goto out;

    ctx->type = typdatum->value;

    rc = mls_context_to_sid(pol, oldc, p, ctx, sidtabp, def_sid);
    if (rc)
        goto out;

    /* Check the validity of the new context. */
    rc = -EINVAL;
    if (!policydb_context_isvalid(pol, ctx))
        goto out;
    rc = 0;
out:
    if (rc)
        context_destroy(ctx);
    return rc;
}

int security_context_to_sid_with_policy(struct selinux_policy *policy, const char *scontext, u32 scontext_len,
                                               u32 *sid, u32 def_sid, gfp_t gfp_flags)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    char *scontext2, *str = NULL;
    struct context context;
    int rc = 0;

    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;

    /* Copy the string to allow changes and ensure a NUL terminator */
    scontext2 = kmemdup_nul(scontext, scontext_len, gfp_flags);
    if (!scontext2)
        return -ENOMEM;

    // removed: if (!selinux_initialized())
    *sid = SECSID_NULL;

    // removed: if (force)
    // removed: rcu lock
    policydb = &policy->policydb;
    sidtab = policy->sidtab;
    rc = string_to_context_struct(policydb, sidtab, scontext2, &context, def_sid);
    if (rc)
        goto out;
    rc = sidtab_context_to_sid(sidtab, &context, sid);
    // rc should not be frozen
    if (rc)
        goto out;
    // removed: if (rc == -ESTALE)
    context_destroy(&context);
out:
    kfree(scontext2);
    kfree(str);
    return rc;
}

/*
 * Write the security context string representation of
 * the context structure `context' into a dynamically
 * allocated string of the correct size.  Set `*scontext'
 * to point to this string and set `*scontext_len' to
 * the length of the string.
 */
static int context_struct_to_string(struct policydb *p, struct context *context, char **scontext, u32 *scontext_len)
{
    char *scontextp;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    if (context->len) {
        *scontext_len = context->len;
        if (scontext) {
            *scontext = kstrdup(context->str, GFP_ATOMIC);
            if (!(*scontext))
                return -ENOMEM;
        }
        return 0;
    }

    /* Compute the size of the context. */
    *scontext_len += strlen(sym_name(p, SYM_USERS, context->user - 1)) + 1;
    *scontext_len += strlen(sym_name(p, SYM_ROLES, context->role - 1)) + 1;
    *scontext_len += strlen(sym_name(p, SYM_TYPES, context->type - 1)) + 1;
    *scontext_len += mls_compute_context_len(p, context);

    if (!scontext)
        return 0;

    /* Allocate space for the context; caller must free this space. */
    scontextp = kmalloc(*scontext_len, GFP_ATOMIC);
    if (!scontextp)
        return -ENOMEM;
    *scontext = scontextp;

    /*
     * Copy the user name, role name and type name into the context.
     */
    scontextp += sprintf(scontextp, "%s:%s:%s", sym_name(p, SYM_USERS, context->user - 1),
                         sym_name(p, SYM_ROLES, context->role - 1), sym_name(p, SYM_TYPES, context->type - 1));

    mls_sid_to_context(p, context, &scontextp);

    *scontextp = 0;

    return 0;
}

static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab, struct sidtab_entry *entry,
                                  char **scontext, u32 *scontext_len)
{
    int rc = sidtab_sid2str_get(sidtab, entry, scontext, scontext_len);

    if (rc != -ENOENT)
        return rc;

    rc = context_struct_to_string(p, &entry->context, scontext, scontext_len);
    if (!rc && scontext)
        sidtab_sid2str_put(sidtab, entry, *scontext, *scontext_len);
    return rc;
}

int security_sid_to_context_with_policy(struct selinux_policy *policy, u32 sid, char **scontext,
                                               u32 *scontext_len)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    struct sidtab_entry *entry;
    int rc = 0;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    // removed: if (!selinux_initialized())
    // removed: rcu lock
    policydb = &policy->policydb;
    sidtab = policy->sidtab;

    // removed: force
    entry = sidtab_search_entry(sidtab, sid);
    if (!entry) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, sid);
        rc = -EINVAL;
        goto out_unlock;
    }
    // removed: only_invalid

    rc = sidtab_entry_to_string(policydb, sidtab, entry, scontext, scontext_len);

out_unlock:
    return rc;
}

static void avd_init(struct selinux_policy *policy, struct av_decision *avd)
{
    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    if (policy)
        avd->seqno = policy->latest_granting;
    else
        avd->seqno = 0;
    avd->flags = 0;
}

static void context_struct_compute_av(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                      u16 tclass, struct av_decision *avd, struct extended_perms *xperms);

/*
 * security_boundary_permission - drops violated permissions
 * on boundary constraint.
 */
static void __nocfi type_attribute_bounds_av(struct policydb *policydb, struct context *scontext,
                                             struct context *tcontext, u16 tclass, struct av_decision *avd)
{
    struct context lo_scontext;
    struct context lo_tcontext, *tcontextp = tcontext;
    struct av_decision lo_avd;
    struct type_datum *source;
    struct type_datum *target;
    u32 masked = 0;

    source = policydb->type_val_to_struct[scontext->type - 1];
    BUG_ON(!source);

    if (!source->bounds)
        return;

    target = policydb->type_val_to_struct[tcontext->type - 1];
    BUG_ON(!target);

    memset(&lo_avd, 0, sizeof(lo_avd));

    memcpy(&lo_scontext, scontext, sizeof(lo_scontext));
    lo_scontext.type = source->bounds;

    if (target->bounds) {
        memcpy(&lo_tcontext, tcontext, sizeof(lo_tcontext));
        lo_tcontext.type = target->bounds;
        tcontextp = &lo_tcontext;
    }

    context_struct_compute_av(policydb, &lo_scontext, tcontextp, tclass, &lo_avd, NULL);

    masked = ~lo_avd.allowed & avd->allowed;

    if (likely(!masked))
        return; /* no masked permission */

    /* mask violated permissions */
    avd->allowed &= ~masked;

    /* audit masked permissions */
    if (security_dump_masked_av_fn)
        security_dump_masked_av_fn(policydb, scontext, tcontext, tclass, masked, "bounds");
}

/*
 * Return the boolean value of a constraint expression
 * when it is applied to the specified source and target
 * security contexts.
 *
 * xcontext is a special beast...  It is used by the validatetrans rules
 * only.  For these rules, scontext is the context before the transition,
 * tcontext is the context after the transition, and xcontext is the context
 * of the process performing the transition.  All other callers of
 * constraint_expr_eval should pass in NULL for xcontext.
 */
static int constraint_expr_eval(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                struct context *xcontext, struct constraint_expr *cexpr)
{
    u32 val1, val2;
    struct context *c;
    struct role_datum *r1, *r2;
    struct mls_level *l1, *l2;
    struct constraint_expr *e;
    int s[CEXPR_MAXDEPTH];
    int sp = -1;

    for (e = cexpr; e; e = e->next) {
        switch (e->expr_type) {
        case CEXPR_NOT:
            BUG_ON(sp < 0);
            s[sp] = !s[sp];
            break;
        case CEXPR_AND:
            BUG_ON(sp < 1);
            sp--;
            s[sp] &= s[sp + 1];
            break;
        case CEXPR_OR:
            BUG_ON(sp < 1);
            sp--;
            s[sp] |= s[sp + 1];
            break;
        case CEXPR_ATTR:
            if (sp == (CEXPR_MAXDEPTH - 1))
                return 0;
            switch (e->attr) {
            case CEXPR_USER:
                val1 = scontext->user;
                val2 = tcontext->user;
                break;
            case CEXPR_TYPE:
                val1 = scontext->type;
                val2 = tcontext->type;
                break;
            case CEXPR_ROLE:
                val1 = scontext->role;
                val2 = tcontext->role;
                r1 = policydb->role_val_to_struct[val1 - 1];
                r2 = policydb->role_val_to_struct[val2 - 1];
                switch (e->op) {
                case CEXPR_DOM:
                    s[++sp] = ebitmap_get_bit(&r1->dominates, val2 - 1);
                    continue;
                case CEXPR_DOMBY:
                    s[++sp] = ebitmap_get_bit(&r2->dominates, val1 - 1);
                    continue;
                case CEXPR_INCOMP:
                    s[++sp] =
                        (!ebitmap_get_bit(&r1->dominates, val2 - 1) && !ebitmap_get_bit(&r2->dominates, val1 - 1));
                    continue;
                default:
                    break;
                }
                break;
            case CEXPR_L1L2:
                l1 = &(scontext->range.level[0]);
                l2 = &(tcontext->range.level[0]);
                goto mls_ops;
            case CEXPR_L1H2:
                l1 = &(scontext->range.level[0]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            case CEXPR_H1L2:
                l1 = &(scontext->range.level[1]);
                l2 = &(tcontext->range.level[0]);
                goto mls_ops;
            case CEXPR_H1H2:
                l1 = &(scontext->range.level[1]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            case CEXPR_L1H1:
                l1 = &(scontext->range.level[0]);
                l2 = &(scontext->range.level[1]);
                goto mls_ops;
            case CEXPR_L2H2:
                l1 = &(tcontext->range.level[0]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            mls_ops:
                switch (e->op) {
                case CEXPR_EQ:
                    s[++sp] = mls_level_eq(l1, l2);
                    continue;
                case CEXPR_NEQ:
                    s[++sp] = !mls_level_eq(l1, l2);
                    continue;
                case CEXPR_DOM:
                    s[++sp] = mls_level_dom(l1, l2);
                    continue;
                case CEXPR_DOMBY:
                    s[++sp] = mls_level_dom(l2, l1);
                    continue;
                case CEXPR_INCOMP:
                    s[++sp] = mls_level_incomp(l2, l1);
                    continue;
                default:
                    BUG();
                    return 0;
                }
                break;
            default:
                BUG();
                return 0;
            }

            switch (e->op) {
            case CEXPR_EQ:
                s[++sp] = (val1 == val2);
                break;
            case CEXPR_NEQ:
                s[++sp] = (val1 != val2);
                break;
            default:
                BUG();
                return 0;
            }
            break;
        case CEXPR_NAMES:
            if (sp == (CEXPR_MAXDEPTH - 1))
                return 0;
            c = scontext;
            if (e->attr & CEXPR_TARGET)
                c = tcontext;
            else if (e->attr & CEXPR_XTARGET) {
                c = xcontext;
                if (!c) {
                    BUG();
                    return 0;
                }
            }
            if (e->attr & CEXPR_USER)
                val1 = c->user;
            else if (e->attr & CEXPR_ROLE)
                val1 = c->role;
            else if (e->attr & CEXPR_TYPE)
                val1 = c->type;
            else {
                BUG();
                return 0;
            }

            switch (e->op) {
            case CEXPR_EQ:
                s[++sp] = ebitmap_get_bit(&e->names, val1 - 1);
                break;
            case CEXPR_NEQ:
                s[++sp] = !ebitmap_get_bit(&e->names, val1 - 1);
                break;
            default:
                BUG();
                return 0;
            }
            break;
        default:
            BUG();
            return 0;
        }
    }

    BUG_ON(sp != 0);
    return s[0];
}

/*
 * Compute access vectors and extended permissions based on a context
 * structure pair for the permissions in a particular class.
 */
static void context_struct_compute_av(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                      u16 tclass, struct av_decision *avd, struct extended_perms *xperms)
{
    struct constraint_node *constraint;
    struct role_allow *ra;
    struct avtab_key avkey;
    struct avtab_node *node;
    struct class_datum *tclass_datum;
    struct ebitmap *sattr, *tattr;
    struct ebitmap_node *snode, *tnode;
    unsigned int i, j;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    if (xperms) {
        memset(&xperms->drivers, 0, sizeof(xperms->drivers));
        xperms->len = 0;
    }

    if (unlikely(!tclass || tclass > policydb->p_classes.nprim)) {
        pr_warn_ratelimited("SELinux:  Invalid class %u\n", tclass);
        return;
    }

    tclass_datum = policydb->class_val_to_struct[tclass - 1];

    /*
     * If a specific type enforcement rule was defined for
     * this permission check, then use it.
     */
    avkey.target_class = tclass;
    avkey.specified = AVTAB_AV | AVTAB_XPERMS;
    sattr = &policydb->type_attr_map_array[scontext->type - 1];
    tattr = &policydb->type_attr_map_array[tcontext->type - 1];
    ebitmap_for_each_positive_bit(sattr, snode, i)
    {
        ebitmap_for_each_positive_bit(tattr, tnode, j)
        {
            avkey.source_type = i + 1;
            avkey.target_type = j + 1;
            for (node = avtab_search_node(&policydb->te_avtab, &avkey); node;
                 node = avtab_search_node_next(node, avkey.specified)) {
                if (node->key.specified == AVTAB_ALLOWED)
                    avd->allowed |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITALLOW)
                    avd->auditallow |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITDENY)
                    avd->auditdeny &= node->datum.u.data;
                else if (xperms && (node->key.specified & AVTAB_XPERMS))
                    services_compute_xperms_drivers(xperms, node);
            }

            /* Check conditional av table for additional permissions */
            cond_compute_av(&policydb->te_cond_avtab, &avkey, avd, xperms);
        }
    }

    /*
     * Remove any permissions prohibited by a constraint (this includes
     * the MLS policy).
     */
    constraint = tclass_datum->constraints;
    while (constraint) {
        if ((constraint->permissions & (avd->allowed)) &&
            !constraint_expr_eval(policydb, scontext, tcontext, NULL, constraint->expr)) {
            avd->allowed &= ~(constraint->permissions);
        }
        constraint = constraint->next;
    }

    /*
     * If checking process transition permission and the
     * role is changing, then check the (current_role, new_role)
     * pair.
     */
    if (tclass == policydb->process_class && (avd->allowed & policydb->process_trans_perms) &&
        scontext->role != tcontext->role) {
        for (ra = policydb->role_allow; ra; ra = ra->next) {
            if (scontext->role == ra->role && tcontext->role == ra->new_role)
                break;
        }
        if (!ra)
            avd->allowed &= ~policydb->process_trans_perms;
    }

    /*
     * If the given source and target types have boundary
     * constraint, lazy checks have to mask any violated
     * permission and notice it to userspace via audit.
     */
    type_attribute_bounds_av(policydb, scontext, tcontext, tclass, avd);
}

void __nocfi security_compute_av_user_with_policy(struct selinux_policy *policy, u32 ssid, u32 tsid, u16 tclass,
                                                         struct av_decision *avd)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    struct context *scontext = NULL, *tcontext = NULL;

    // remove: rcu lock
    avd_init(policy, avd);
    // remove: if (!selinux_initialized())

    policydb = &policy->policydb;
    sidtab = policy->sidtab;

    scontext = sidtab_search(sidtab, ssid);
    if (!scontext) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, ssid);
        goto out;
    }

    /* permissive domain? */
    if (ebitmap_get_bit(&policydb->permissive_map, scontext->type))
        avd->flags |= AVD_FLAGS_PERMISSIVE;

    tcontext = sidtab_search(sidtab, tsid);
    if (!tcontext) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, tsid);
        goto out;
    }

    if (unlikely(!tclass)) {
        if (policydb->allow_unknown)
            goto allow;
        goto out;
    }

    if (context_struct_compute_av_fn) {
        context_struct_compute_av_fn(policydb, scontext, tcontext, tclass, avd, NULL);
    } else {
        context_struct_compute_av(policydb, scontext, tcontext, tclass, avd, NULL);
    }
out:
    return;
allow:
    avd->allowed = 0xffffffff;
    goto out;
}
#endif // LINUX_VERSION_CODE >= 6.6
#endif // CONFIG_KSU_SUSFS
