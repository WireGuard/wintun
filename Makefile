#
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
#

!IFNDEF CFG
CFG=Release
!ENDIF
!IFNDEF PLAT
PLAT=x64
!ENDIF
!IF "$(PLAT)" == "Win32"
OUTPUT_DIR=$(CFG)
!ELSE
OUTPUT_DIR=$(PLAT)\$(CFG)
!ENDIF
MSBUILD_FLAGS=/p:Configuration="$(CFG)" /p:Platform="$(PLAT)" /m /v:minimal /nologo

build ::
	msbuild.exe "wintun.vcxproj" /t:Build $(MSBUILD_FLAGS)

clean ::
	msbuild.exe "wintun.vcxproj" /t:Clean $(MSBUILD_FLAGS)

!IF "$(CFG)" == "Release"

dvl :: "wintun.DVL.XML"

clean ::
	msbuild.exe "wintun.vcxproj" /t:sdv /p:Inputs="/clean" $(MSBUILD_FLAGS)
	-if exist "wintun.DVL.XML" del /f /q "wintun.DVL.XML"
	-if exist "smvstats.txt" del /f /q "smvstats.txt"

"sdv\SDV.DVL.xml" "$(OUTPUT_DIR)\vc.nativecodeanalysis.all.xml" :
	msbuild.exe "wintun.vcxproj" /t:sdv /p:Inputs="/check:*" $(MSBUILD_FLAGS)

"wintun.DVL.XML" : "sdv\SDV.DVL.xml" "$(OUTPUT_DIR)\vc.nativecodeanalysis.all.xml"
	msbuild.exe "wintun.vcxproj" /t:dvl $(MSBUILD_FLAGS)

!ENDIF
