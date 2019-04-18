#
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
#

!IF "$(PLAT)" == "x86"
PLAT_MSBUILD=Win32
PLAT_WIX=x86
!ELSEIF "$(PLAT)" == "amd64"
PLAT_MSBUILD=x64
PLAT_WIX=x64
!ELSEIF "$(PLAT)" == "arm64"
PLAT_MSBUILD=ARM64
PLAT_WIX=arm64 # TODO: Follow WiX ARM64 support.
!ELSE
!ERROR Invalid platform "$(PLAT)". PLAT must be "x86", "amd64", or "arm64".
!ENDIF

OUTPUT_DIR=$(PLAT)\$(CFG)

build_$(PLAT)_$(CFG) ::
	msbuild.exe "wintun.vcxproj" /t:Build /p:Configuration="$(CFG)" /p:Platform="$(PLAT_MSBUILD)" $(MSBUILD_FLAGS)

clean ::
	-rd /s /q "$(OUTPUT_DIR)" > NUL 2>&1

!IF "$(CFG)" == "Release"

"$(OUTPUT_DIR)\wintun.wixobj" : "wintun.wxs"
	"$(WIX)bin\candle.exe" $(WIX_CANDLE_FLAGS) -arch "$(PLAT_WIX)" -out $@ $**

"$(DIST_DIR)\wintun-$(PLAT)-$(WINTUN_VERSION).msm" : \
	"$(DIST_DIR)" \
	"$(OUTPUT_DIR)\wintun.cer" \
	"$(OUTPUT_DIR)\wintun\wintun.cat" \
	"$(OUTPUT_DIR)\wintun\wintun.inf" \
	"$(OUTPUT_DIR)\wintun\wintun.sys" \
	"$(OUTPUT_DIR)\wintun.wixobj" \
	"$(WIX)bin\difxapp_$(PLAT_WIX).wixlib"
	"$(WIX)bin\light.exe" $(WIX_LIGHT_FLAGS) -b output_dir="$(OUTPUT_DIR)" -out $@ -spdb "$(OUTPUT_DIR)\wintun.wixobj" "$(WIX)bin\difxapp_$(PLAT_WIX).wixlib"

!ENDIF
