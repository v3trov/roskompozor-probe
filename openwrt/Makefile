include $(TOPDIR)/rules.mk

PKG_NAME:=roskompozor-probe
PKG_VERSION:=1.0.2
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/roskompozor-probe
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Lightweight native Roskompozor diagnostics probe
  URL:=https://github.com/v3trov/roskompozor-probe
  DEPENDS:=+libopenssl +libjson-c +libcurl +libidn +ca-bundle +libpthread +iputils-ping
endef

define Package/roskompozor-probe/description
  Native C client: public DNS, ICMP, TCP, verified TLS and HTTP/HTTPS.
  Compatible with the existing Roskompozor Probe API. No Python runtime.
endef

define Package/roskompozor-probe/conffiles
/etc/roskompozor-probe/config.json
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -std=c11 -Os \
		-Wall -Wextra -Werror -Wno-misleading-indentation \
		-ffunction-sections -fdata-sections \
		-I$(STAGING_DIR)/usr/include/json-c \
		$(PKG_BUILD_DIR)/probe.c $(TARGET_LDFLAGS) -Wl,--gc-sections \
		-lssl -lcrypto -ljson-c -lcurl -lidn -lpthread -lm \
		-o $(PKG_BUILD_DIR)/roskompozor-probe
endef

define Package/roskompozor-probe/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/roskompozor-probe
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/roskompozor-probe $(1)/usr/bin/
	$(INSTALL_BIN) ./files/roskompozor-probe.init $(1)/etc/init.d/roskompozor-probe
	$(INSTALL_CONF) ./files/config.json $(1)/etc/roskompozor-probe/config.json
	chmod 600 $(1)/etc/roskompozor-probe/config.json
endef

$(eval $(call BuildPackage,roskompozor-probe))
