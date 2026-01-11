@echo off
setlocal enabledelayedexpansion

:: HolyTLS Windows Build Script
:: Requires: Visual Studio 2022, CMake, Go (for BoringSSL)

set BUILD_DIR=build
set BUILD_TYPE=Release
set GENERATOR=Visual Studio 17 2022
set PLATFORM=x64

:: Parse command line arguments
:parse_args
if "%~1"=="" goto :done_args
if /i "%~1"=="debug" (
    set BUILD_TYPE=Debug
    shift
    goto :parse_args
)
if /i "%~1"=="release" (
    set BUILD_TYPE=Release
    shift
    goto :parse_args
)
if /i "%~1"=="clean" (
    echo Cleaning build directory...
    if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
    echo Done.
    exit /b 0
)
if /i "%~1"=="--help" goto :show_help
if /i "%~1"=="-h" goto :show_help
shift
goto :parse_args

:done_args

:: Check for required tools
where cmake >nul 2>&1
if errorlevel 1 (
    echo ERROR: cmake not found in PATH
    echo Please install CMake and add it to your PATH
    exit /b 1
)

where go >nul 2>&1
if errorlevel 1 (
    echo ERROR: go not found in PATH
    echo Go is required to build BoringSSL
    echo Please install Go from https://go.dev/dl/
    exit /b 1
)

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Configure
echo.
echo ========================================
echo Configuring HolyTLS (%BUILD_TYPE%)
echo Generator: %GENERATOR%
echo Platform: %PLATFORM%
echo ========================================
echo.

cmake -B %BUILD_DIR% -G "%GENERATOR%" -A %PLATFORM% -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo.
    echo ERROR: CMake configuration failed
    exit /b 1
)

:: Build
echo.
echo ========================================
echo Building HolyTLS (%BUILD_TYPE%)
echo ========================================
echo.

cmake --build %BUILD_DIR% --config %BUILD_TYPE% --parallel
if errorlevel 1 (
    echo.
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ========================================
echo Build successful!
echo ========================================
echo.
echo Binaries are in: %BUILD_DIR%\%BUILD_TYPE%\
echo.
echo Examples:
echo   %BUILD_DIR%\%BUILD_TYPE%\fingerprint_check.exe
echo   %BUILD_DIR%\%BUILD_TYPE%\async_example.exe
echo.

exit /b 0

:show_help
echo.
echo HolyTLS Windows Build Script
echo.
echo Usage: build.bat [options]
echo.
echo Options:
echo   release    Build Release configuration (default)
echo   debug      Build Debug configuration
echo   clean      Remove build directory
echo   --help     Show this help message
echo.
echo Examples:
echo   build.bat              Build Release
echo   build.bat debug        Build Debug
echo   build.bat clean        Clean build directory
echo.
exit /b 0
