mod_capsvm_api.la: mod_capsvm_api.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_capsvm_api.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_capsvm_api.la
