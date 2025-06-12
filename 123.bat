@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo =====================================
echo     DRM 项目文件夹整理工具
echo =====================================
echo.

:: 检查当前目录是否包含项目文件
if not exist "WpfApp1.csproj" (
    echo 错误：当前目录不包含 WpfApp1.csproj 文件
    echo 请确保在正确的项目目录中运行此脚本
    pause
    exit /b 1
)

echo 当前目录：%CD%
echo.
echo 将要执行以下操作：
echo 1. 创建备份文件夹
echo 2. 创建新的项目结构
echo 3. 移动和重命名文件
echo 4. 删除临时文件
echo.

set /p confirm="确认执行整理操作？(Y/N): "
if /i not "%confirm%"=="Y" (
    echo 操作已取消
    pause
    exit /b 0
)

echo.
echo ==========================================
echo 步骤 1: 创建备份
echo ==========================================

:: 创建带时间戳的备份文件夹
for /f "tokens=2-4 delims=/ " %%a in ('date /t') do set mydate=%%c%%a%%b
for /f "tokens=1-2 delims=/:" %%a in ('time /t') do set mytime=%%a%%b
set mytime=%mytime: =0%
set backup_folder=backup_%mydate%_%mytime%

echo 创建备份文件夹: %backup_folder%
mkdir "%backup_folder%" 2>nul
if errorlevel 1 (
    echo 警告：无法创建备份文件夹
) else (
    echo 备份原始文件...
    copy /Y *.* "%backup_folder%\" >nul 2>&1
    echo 备份完成
)

echo.
echo ==========================================
echo 步骤 2: 创建新的项目结构
echo ==========================================

echo 创建项目文件夹结构...
mkdir "DRM" 2>nul
mkdir "DRM\Models" 2>nul
mkdir "DRM\Managers" 2>nul
mkdir "DRM\Helpers" 2>nul

echo 文件夹结构创建完成

echo.
echo ==========================================
echo 步骤 3: 移动和重命名文件
echo ==========================================

:: 重命名并移动解决方案文件
echo 处理解决方案文件...
if exist "WpfApp1.sln" (
    move "WpfApp1.sln" "DRM.sln" >nul
    echo ✓ WpfApp1.sln → DRM.sln
)

:: 重命名并移动项目文件
echo 处理项目文件...
if exist "WpfApp1.csproj" (
    move "WpfApp1.csproj" "DRM\DRM.csproj" >nul
    echo ✓ WpfApp1.csproj → DRM\DRM.csproj
)

:: 移动核心应用文件到DRM文件夹
echo 移动核心应用文件...
for %%f in (App.xaml App.xaml.cs app.manifest AssemblyInfo.cs MainWindow.xaml MainWindow.xaml.cs DiagnosticWindow.xaml DiagnosticWindow.xaml.cs Resources.resx) do (
    if exist "%%f" (
        move "%%f" "DRM\" >nul
        echo ✓ %%f → DRM\
    )
)

:: 移动模型文件
echo 移动模型文件...
for %%f in (ServerConfig.cs SystemDiagnostics.cs) do (
    if exist "%%f" (
        move "%%f" "DRM\Models\" >nul
        echo ✓ %%f → DRM\Models\
    )
)

:: 移动管理器文件
echo 移动管理器文件...
for %%f in (ActivationStateManager.cs NetworkManager.cs ResourceManager.cs SecurityManager.cs VirtualFileSystemManager.cs) do (
    if exist "%%f" (
        move "%%f" "DRM\Managers\" >nul
        echo ✓ %%f → DRM\Managers\
    )
)

:: 移动帮助类文件
echo 移动帮助类文件...
for %%f in (HardwareIdHelper.cs) do (
    if exist "%%f" (
        move "%%f" "DRM\Helpers\" >nul
        echo ✓ %%f → DRM\Helpers\
    )
)

echo.
echo ==========================================
echo 步骤 4: 清理临时文件
echo ==========================================

:: 删除不需要的文件
if exist "新建 文本文档.txt" (
    del "新建 文本文档.txt" >nul
    echo ✓ 删除临时文件: 新建 文本文档.txt
)

echo.
echo ==========================================
echo 步骤 5: 更新项目文件引用
echo ==========================================

:: 更新解决方案文件中的项目路径
if exist "DRM.sln" (
    echo 更新解决方案文件引用...
    powershell -Command "(Get-Content 'DRM.sln') -replace 'WpfApp1\.csproj', 'DRM\DRM.csproj' -replace 'WpfApp1', 'DRM' | Set-Content 'DRM.sln'" 2>nul
    if errorlevel 1 (
        echo 警告：无法自动更新解决方案文件，请手动编辑
    ) else (
        echo ✓ 解决方案文件引用已更新
    )
)

:: 更新项目文件中的程序集名称和根命名空间
if exist "DRM\DRM.csproj" (
    echo 更新项目文件配置...
    powershell -Command "(Get-Content 'DRM\DRM.csproj') -replace '<RootNamespace>WpfApp1</RootNamespace>', '<RootNamespace>DRM</RootNamespace>' -replace '<AssemblyName>WpfApp1</AssemblyName>', '<AssemblyName>DRM</AssemblyName>' | Set-Content 'DRM\DRM.csproj'" 2>nul
    if errorlevel 1 (
        echo 警告：无法自动更新项目文件，请手动编辑
    ) else (
        echo ✓ 项目文件配置已更新
    )
)

echo.
echo ==========================================
echo 整理完成！
echo ==========================================
echo.
echo 项目文件已重新组织，新的结构：
echo ├── DRM.sln (解决方案文件)
echo ├── .gitattributes
echo ├── .gitignore  
echo └── DRM\ (项目文件夹)
echo     ├── DRM.csproj
echo     ├── 核心文件 (App.xaml, MainWindow.xaml 等)
echo     ├── Models\ (ServerConfig.cs, SystemDiagnostics.cs)
echo     ├── Managers\ (各种Manager类)
echo     └── Helpers\ (HardwareIdHelper.cs)
echo.
echo 重要提醒：
echo 1. 备份文件位于: %backup_folder%\
echo 2. 请手动更新所有 .cs 文件中的命名空间：
echo    将 "namespace WpfApp1" 改为 "namespace DRM"
echo 3. 用 Visual Studio 打开 DRM.sln 验证项目是否正常
echo 4. 如有问题，可从备份文件夹恢复
echo.

pause
echo.
echo 是否现在用 Visual Studio 打开项目？(Y/N): 
set /p open_vs=""
if /i "!open_vs!"=="Y" (
    if exist "DRM.sln" (
        echo 正在打开 Visual Studio...
        start "Visual Studio" "DRM.sln"
    ) else (
        echo 错误：找不到 DRM.sln 文件
    )
)

echo.
echo 脚本执行完成。
pause