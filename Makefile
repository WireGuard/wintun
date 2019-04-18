#
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
#

# TODO: Unify version definition with wintun.vcxproj. Migrate from NMAKE to MSBuild?
WINTUN_VERSION=0.1

DIST_DIR=dist
MSBUILD_FLAGS=/m /v:minimal /nologo
WIX_CANDLE_FLAGS=-nologo -ext WixDifxAppExtension -ext WixIIsExtension -dWINTUN_VERSION="$(WINTUN_VERSION)"
WIX_LIGHT_FLAGS=-nologo -ext WixDifxAppExtension -ext WixIIsExtension -sw1103

build :: \
	build_x86_Release \
	build_amd64_Release \
	build_arm64_Release

dvl :: "wintun.DVL.XML"

msm :: \
	"$(DIST_DIR)" \
	"$(DIST_DIR)\wintun_$(WINTUN_VERSION)_x86.msm" \
	"$(DIST_DIR)\wintun_$(WINTUN_VERSION)_amd64.msm"

"sdv\SDV.DVL.xml" "amd64\Release\vc.nativecodeanalysis.all.xml" :
	msbuild.exe "wintun.vcxproj" /t:sdv /p:Inputs="/check:*" /p:Configuration="Release" /p:Platform="x64" $(MSBUILD_FLAGS)

"wintun.DVL.XML" : "sdv\SDV.DVL.xml" "amd64\Release\vc.nativecodeanalysis.all.xml"
	msbuild.exe "wintun.vcxproj" /t:dvl /p:Configuration="Release" /p:Platform="x64" $(MSBUILD_FLAGS)

"$(DIST_DIR)" :
	md $@ > NUL 2>&1

clean ::
	-rd /s /q "sdv"             > NUL 2>&1
	-del /f /q "wintun.DVL.XML" > NUL 2>&1
	-del /f /q "smvbuild.log"   > NUL 2>&1
	-del /f /q "smvstats.txt"   > NUL 2>&1
	-rd /s /q "$(DIST_DIR)"     > NUL 2>&1

CFG=Release
PLAT=x86
!INCLUDE "Makefile.PlatCfg.mak"
PLAT=amd64
!INCLUDE "Makefile.PlatCfg.mak"
PLAT=arm64
!INCLUDE "Makefile.PlatCfg.mak"

CFG=Debug
PLAT=x86
!INCLUDE "Makefile.PlatCfg.mak"
PLAT=amd64
!INCLUDE "Makefile.PlatCfg.mak"
PLAT=arm64
!INCLUDE "Makefile.PlatCfg.mak"
