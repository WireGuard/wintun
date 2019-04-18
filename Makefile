#
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
#

# TODO: Unify version definition with wintun.vcxproj.
WINTUN_VERSION_MAJ=0
WINTUN_VERSION_MIN=0
WINTUN_VERSION_REV=2019
WINTUN_VERSION_BUILD=0128
WINTUN_VERSION=$(WINTUN_VERSION_MAJ).$(WINTUN_VERSION_MIN).$(WINTUN_VERSION_REV).$(WINTUN_VERSION_BUILD)

!IFNDEF CFG
CFG=Release
!ENDIF
!IFNDEF PLAT
PLAT=amd64
!ENDIF
!IF "$(PLAT)" == "x86" || "$(PLAT)" == "X86"
PLAT=x86
PLAT_MSBUILD=Win32
PLAT_WIX=x86
!ELSEIF "$(PLAT)" == "amd64" || "$(PLAT)" == "AMD64"
PLAT=amd64
PLAT_MSBUILD=x64
PLAT_WIX=x64
!ELSEIF "$(PLAT)" == "arm64" || "$(PLAT)" == "ARM64"
PLAT=arm64
PLAT_MSBUILD=ARM64
PLAT_WIX=arm64 # TODO: Follow WiX ARM64 support.
!ELSE
!ERROR Invalid platform "$(PLAT)". PLAT must be "x86", "amd64", or "arm64".
!ENDIF
DIST_DIR=dist
OUTPUT_DIR=$(PLAT)\$(CFG)
MSM_NAME=wintun_$(WINTUN_VERSION)_$(PLAT)
MSBUILD_FLAGS=/p:Configuration="$(CFG)" /p:Platform="$(PLAT_MSBUILD)" /m /v:minimal /nologo
WIX_CANDLE_FLAGS=-nologo -ext WixDifxAppExtension -ext WixIIsExtension -arch "$(PLAT_WIX)" -dWINTUN_VERSION="$(WINTUN_VERSION)"
WIX_LIGHT_FLAGS=-nologo -ext WixDifxAppExtension -ext WixIIsExtension -b output_dir="$(OUTPUT_DIR)" -sw1103

build ::
	msbuild.exe "wintun.vcxproj" /t:Build $(MSBUILD_FLAGS)

clean ::
	-rd /s /q "$(DIST_DIR)"   > NUL 2>&1
	-rd /s /q "$(OUTPUT_DIR)" > NUL 2>&1

!IF "$(CFG)" == "Release" && "$(PLAT)" != "arm64"

dvl :: "wintun.DVL.XML"

clean ::
	-rd /s /q "sdv"             > NUL 2>&1
	-del /f /q "wintun.DVL.XML" > NUL 2>&1
	-del /f /q "smvbuild.log"   > NUL 2>&1
	-del /f /q "smvstats.txt"   > NUL 2>&1

"sdv\SDV.DVL.xml" "$(OUTPUT_DIR)\vc.nativecodeanalysis.all.xml" :
	msbuild.exe "wintun.vcxproj" /t:sdv /p:Inputs="/check:*" $(MSBUILD_FLAGS)

"wintun.DVL.XML" : "sdv\SDV.DVL.xml" "$(OUTPUT_DIR)\vc.nativecodeanalysis.all.xml"
	msbuild.exe "wintun.vcxproj" /t:dvl $(MSBUILD_FLAGS)

msm :: "$(DIST_DIR)\$(MSM_NAME).msm"

"$(OUTPUT_DIR)\wintun.wixobj" : "wintun.wxs"
	"$(WIX)bin\candle.exe" $(WIX_CANDLE_FLAGS) -out $@ $**

"$(DIST_DIR)\$(MSM_NAME).msm" : \
	"$(DIST_DIR)" \
	"$(OUTPUT_DIR)\wintun.cer" \
	"$(OUTPUT_DIR)\wintun\wintun.cat" \
	"$(OUTPUT_DIR)\wintun\wintun.inf" \
	"$(OUTPUT_DIR)\wintun\wintun.sys" \
	"$(OUTPUT_DIR)\wintun.wixobj" \
	"$(WIX)bin\difxapp_$(PLAT_WIX).wixlib"
	"$(WIX)bin\light.exe" $(WIX_LIGHT_FLAGS) -out "$(DIST_DIR)\$(MSM_NAME).msm" -spdb "$(OUTPUT_DIR)\wintun.wixobj" "$(WIX)bin\difxapp_$(PLAT_WIX).wixlib"

!ENDIF

"$(DIST_DIR)" :
	md $@ > NUL 2>&1
