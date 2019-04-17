#
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
#

# TODO: Unify version definition with wintun.vcxproj.
WINTUN_VERSION_MAJ=0
WINTUN_VERSION_MIN=0
WINTUN_VERSION_REV=2019
WINTUN_VERSION_BUILD=128

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
OUTPUT_DIR=$(PLAT)\$(CFG)
MSBUILD_FLAGS=/p:Configuration="$(CFG)" /p:Platform="$(PLAT_MSBUILD)" /m /v:minimal /nologo
WIX_CANDLE_FLAGS=-nologo -ext WixDifxAppExtension -ext WixIIsExtension -arch "$(PLAT_WIX)" -dWINTUN_VERSION="$(WINTUN_VERSION_MAJ).$(WINTUN_VERSION_MIN).$(WINTUN_VERSION_REV).$(WINTUN_VERSION_BUILD)"
WIX_LIGHT_FLAGS=-nologo -ext WixDifxAppExtension -ext WixIIsExtension -b output_dir="$(OUTPUT_DIR)" -sw1103

build ::
	msbuild.exe "wintun.vcxproj" /t:Build $(MSBUILD_FLAGS)

clean ::
	msbuild.exe "wintun.vcxproj" /t:Clean $(MSBUILD_FLAGS)

!IF "$(CFG)" == "Release" && "$(PLAT)" != "arm64"

dvl :: "wintun.DVL.XML"

clean ::
	msbuild.exe "wintun.vcxproj" /t:sdv /p:Inputs="/clean" $(MSBUILD_FLAGS)
	-del /f /q "wintun.DVL.XML" > NUL 2>&1
	-del /f /q "smvstats.txt"   > NUL 2>&1

"sdv\SDV.DVL.xml" "$(OUTPUT_DIR)\vc.nativecodeanalysis.all.xml" :
	msbuild.exe "wintun.vcxproj" /t:sdv /p:Inputs="/check:*" $(MSBUILD_FLAGS)

"wintun.DVL.XML" : "sdv\SDV.DVL.xml" "$(OUTPUT_DIR)\vc.nativecodeanalysis.all.xml"
	msbuild.exe "wintun.vcxproj" /t:dvl $(MSBUILD_FLAGS)

!ENDIF

msm :: "$(OUTPUT_DIR)\wintun.msm"

clean ::
	-del /f /q "$(OUTPUT_DIR)\wintun.wixobj" > NUL 2>&1
	-del /f /q "$(OUTPUT_DIR)\wintun.wixpdb" > NUL 2>&1
	-del /f /q "$(OUTPUT_DIR)\wintun.msm"    > NUL 2>&1

"$(OUTPUT_DIR)\wintun.wixobj" : "wintun.wxs"
	"$(WIX)bin\candle.exe" $(WIX_CANDLE_FLAGS) -out $@ $**

"$(OUTPUT_DIR)\wintun.msm" "$(OUTPUT_DIR)\wintun.wixpdb" : \
	"$(OUTPUT_DIR)\wintun.cer" \
	"$(OUTPUT_DIR)\wintun\wintun.cat" \
	"$(OUTPUT_DIR)\wintun\wintun.inf" \
	"$(OUTPUT_DIR)\wintun\wintun.sys" \
	"$(OUTPUT_DIR)\wintun.wixobj" \
	"$(WIX)bin\difxapp_$(PLAT_WIX).wixlib"
	"$(WIX)bin\light.exe" $(WIX_LIGHT_FLAGS) -out "$(OUTPUT_DIR)\wintun.msm" "$(OUTPUT_DIR)\wintun.wixobj" "$(WIX)bin\difxapp_$(PLAT_WIX).wixlib"
