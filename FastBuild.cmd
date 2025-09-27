@set SLND=%~dp0
@if not exist "%SLND%Build\Bins\AMD64" md "%SLND%Build\Bins\AMD64"
@if not exist "%SLND%Build\Objs\Falcon\AMD64" md "%SLND%Build\Objs\Falcon\AMD64"

@echo building x64

:x64
@cd /d "%SLND%Projects\Falcon"
@NMAKE /NOLOGO PLATFORM=x64 PROJ=Falcon

@cd /d "%SLND%"
