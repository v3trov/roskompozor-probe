include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-roskompozor-probe
PKG_VERSION:=1.0.0
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-roskompozor-probe
  PKGARCH:=all
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI configuration for Roskompozor Probe
  DEPENDS:=+luci-base +rpcd-mod-file +roskompozor-probe
endef

define Build/Compile
endef

define Package/luci-app-roskompozor-probe/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view
	$(INSTALL_DATA) ./files/roskompozor-probe.js $(1)/www/luci-static/resources/view/
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d $(1)/usr/libexec
	$(INSTALL_DATA) ./files/menu.json $(1)/usr/share/luci/menu.d/luci-app-roskompozor-probe.json
	$(INSTALL_DATA) ./files/acl.json $(1)/usr/share/rpcd/acl.d/luci-app-roskompozor-probe.json
	$(INSTALL_BIN) ./files/config-helper $(1)/usr/libexec/roskompozor-probe-config
endef

define Package/luci-app-roskompozor-probe/postinst
#!/bin/sh
if [ -z "$$IPKG_INSTROOT" ]; then
  rm -f /tmp/luci-indexcache /tmp/luci-indexcache.*
  /etc/init.d/rpcd reload
fi
exit 0
endef

$(eval $(call BuildPackage,luci-app-roskompozor-probe))
