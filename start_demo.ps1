# APPAD 本地 Demo 一鍵部署腳本
# 用法：雙擊 start_demo.bat，或在 PowerShell 執行 .\start_demo.ps1
# 流程：建立/重用 Python venv → 安裝相依套件 → npm install → 啟動後端 API(8000) → 啟動前端網站(Vite) 並開啟瀏覽器

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$VenvDir = Join-Path $Root ".venv311-tenseal"   # 與 frontend/package.json 的 "api" 指令一致
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$FrontendDir = Join-Path $Root "frontend"
$BackendPort = 8000

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "[錯誤] $msg" -ForegroundColor Red; Read-Host "按 Enter 結束"; exit 1 }

# 執行外部程式並回傳 exit code（吞掉 stderr，避免 PS 5.1 把 stderr 當錯誤丟出）
function Invoke-Quiet($exe, [string[]]$argList) {
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argList -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput (Join-Path $env:TEMP "appad_demo_out.log") `
            -RedirectStandardError (Join-Path $env:TEMP "appad_demo_err.log")
        return $p.ExitCode
    } catch { return 1 }
}

# ---------- 1. 尋找相容的 Python（TenSEAL 需要 <= 3.12） ----------
Write-Step "檢查 Python 環境"
if (-not (Test-Path $VenvPython)) {
    $pyExe = $null
    $pyArgs = @()
    foreach ($ver in @("-3.12", "-3.11", "-3.10")) {
        if ((Invoke-Quiet "py" @($ver, "--version")) -eq 0) {
            $pyExe = "py"; $pyArgs = @($ver); break
        }
    }
    if ($null -eq $pyExe) {
        # 後備：uv 安裝的 CPython（py launcher 註冊名稱不含 -3.11）
        $uvPython = Get-ChildItem "$env:APPDATA\uv\python\cpython-3.1[012]*\python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($uvPython) { $pyExe = $uvPython.FullName }
    }
    if ($null -eq $pyExe) {
        Fail "找不到 Python 3.10~3.12（TenSEAL 不支援 3.13+）。請先安裝 Python 3.12：https://www.python.org/downloads/"
    }
    Write-Host "使用 $pyExe $($pyArgs -join ' ') 建立虛擬環境 $VenvDir"
    & $pyExe @pyArgs -m venv $VenvDir
    if (-not (Test-Path $VenvPython)) { Fail "虛擬環境建立失敗" }
} else {
    Write-Host "已存在虛擬環境：$VenvDir"
}

# ---------- 2. 安裝 Python 相依套件（已裝齊則略過） ----------
Write-Step "檢查 Python 相依套件"
# 注意：引數不能含空格（Start-Process 會拆開），故 import 之間只用逗號
$importCheck = Invoke-Quiet $VenvPython @("-c", "import flask,tenseal,sklearn,pandas,matplotlib,joblib,requests")
if ($importCheck -ne 0) {
    Write-Host "安裝 requirements.txt（首次約需數分鐘）..."
    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install -r (Join-Path $Root "requirements.txt")
    if ($LASTEXITCODE -ne 0) { Fail "pip install 失敗，請檢查網路或錯誤訊息" }
} else {
    Write-Host "相依套件已安裝，略過"
}

# ---------- 3. 前端相依套件 ----------
Write-Step "檢查前端相依套件"
$npm = Get-Command npm -ErrorAction SilentlyContinue
if ($null -eq $npm) { Fail "找不到 npm，請先安裝 Node.js：https://nodejs.org/" }
if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
    Write-Host "執行 npm install ..."
    Push-Location $FrontendDir
    & npm.cmd install
    $npmOk = ($LASTEXITCODE -eq 0)
    Pop-Location
    if (-not $npmOk) { Fail "npm install 失敗" }
} else {
    Write-Host "node_modules 已存在，略過"
}

# ---------- 4. 必要檔案檢查 ----------
Write-Step "檢查必要檔案"
$model = Join-Path $Root "logistic_regression_model\output_lr\lr_model.joblib"
if (-not (Test-Path $model)) { Fail "缺少模型檔 $model（請先執行模型訓練）" }
Write-Host "模型檔 OK"

# ---------- 5. 啟動後端 API ----------
Write-Step "啟動後端 API (port $BackendPort)"
$portInUse = Get-NetTCPConnection -LocalPort $BackendPort -State Listen -ErrorAction SilentlyContinue
$backendProc = $null
if ($portInUse) {
    Write-Host "port $BackendPort 已有服務在執行，沿用現有後端"
} else {
    $backendProc = Start-Process -FilePath $VenvPython -ArgumentList "backend_api.py" `
        -WorkingDirectory $FrontendDir -PassThru -WindowStyle Minimized
    # 等待後端開始監聽（最多 30 秒）
    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        if ($backendProc.HasExited) { break }
        $conn = Get-NetTCPConnection -LocalPort $BackendPort -State Listen -ErrorAction SilentlyContinue
        if ($conn) { $ok = $true; break }
    }
    if (-not $ok) { Fail "後端啟動失敗（30 秒內未監聽 port $BackendPort），請查看最小化的後端視窗錯誤訊息" }
    Write-Host "後端已就緒 (PID $($backendProc.Id))"
}

# ---------- 6. 啟動前端（Vite，會自動開啟瀏覽器） ----------
Write-Step "啟動前端網站（關閉此視窗或按 Ctrl+C 即停止 Demo）"
try {
    Push-Location $FrontendDir
    & npm.cmd run web
} finally {
    Pop-Location
    if ($backendProc -and -not $backendProc.HasExited) {
        Write-Host "`n停止後端 API (PID $($backendProc.Id))"
        Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue
    }
}
