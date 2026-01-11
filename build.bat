@echo off
setlocal enabledelayedexpansion

:: HolyTLS Windows Build Script
:: Requires: Visual Studio 2022, CMake, Ninja, Go (for BoringSSL)
::
:: Uses Ninja generator with MSVC for fast parallel builds.
:: Run from "x64 Native Tools Command Prompt for VS 2022" or run vcvars64.bat first.

set BUILD_DIR=build
set BUILD_TYPE=Release
set USE_NINJA=1

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
if /i "%~1"=="vs" (
    set USE_NINJA=0
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

:: Set up generator - check for Ninja if requested
if !USE_NINJA!==0 goto :use_vs_generator

where ninja >nul 2>&1
if errorlevel 1 (
    echo WARNING: ninja not found, falling back to Visual Studio generator
    echo For faster builds, install Ninja: winget install Ninja-build.Ninja
    set USE_NINJA=0
    goto :use_vs_generator
)

:: Check if MSVC is in PATH (vcvars64.bat was run)
where cl >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: MSVC compiler [cl.exe] not found in PATH
    echo.
    echo To use Ninja with MSVC, run this script from:
    echo   "x64 Native Tools Command Prompt for VS 2022"
    echo.
    echo Or run vcvars64.bat first:
    echo   "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    echo.
    echo Alternatively, use the slower VS generator:
    echo   build.bat vs
    echo.
    exit /b 1
)

set GENERATOR=Ninja
set "CMAKE_EXTRA_ARGS=-DCMAKE_BUILD_TYPE=!BUILD_TYPE!"
goto :generator_done

:use_vs_generator
set GENERATOR=Visual Studio 17 2022
set CMAKE_EXTRA_ARGS=-A x64

:generator_done

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Configure
echo.
echo ========================================
echo Configuring HolyTLS (%BUILD_TYPE%)
echo Generator: %GENERATOR%
echo ========================================
echo.

cmake -B %BUILD_DIR% -G "%GENERATOR%" %CMAKE_EXTRA_ARGS%
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

if !USE_NINJA!==1 (
    cmake --build %BUILD_DIR% --parallel
) else (
    cmake --build %BUILD_DIR% --config %BUILD_TYPE% --parallel
)
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
if !USE_NINJA!==1 (
    echo Binaries are in: %BUILD_DIR%\
    echo.
    echo Examples:
    echo   %BUILD_DIR%\fingerprint_check.exe
    echo   %BUILD_DIR%\async_example.exe
) else (
    echo Binaries are in: %BUILD_DIR%\%BUILD_TYPE%\
    echo.
    echo Examples:
    echo   %BUILD_DIR%\%BUILD_TYPE%\fingerprint_check.exe
    echo   %BUILD_DIR%\%BUILD_TYPE%\async_example.exe
)
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
echo   vs         Use Visual Studio generator (slower, but no vcvars needed)
echo   clean      Remove build directory
echo   --help     Show this help message
echo.
echo For fastest builds, use Ninja (default):
echo   1. Open "x64 Native Tools Command Prompt for VS 2022"
echo   2. Run: build.bat
echo.
echo Or install Ninja: winget install Ninja-build.Ninja
echo.
echo Examples:
echo   build.bat              Build Release with Ninja (fast)
echo   build.bat debug        Build Debug with Ninja
echo   build.bat vs           Build Release with VS generator (slow)
echo   build.bat vs debug     Build Debug with VS generator
echo   build.bat clean        Clean build directory
echo.
exit /b 0
