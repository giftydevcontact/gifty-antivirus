' Launch-Gifty-Antivirus.vbs
' Installed to Program Files alongside gifty_av.py.
' All shortcuts point here so the app opens without a black console window.

Option Explicit

Dim objShell, objFSO, strDir, strScript, strPythonW, strHintFile, strHint

Set objShell = CreateObject("WScript.Shell")
Set objFSO   = CreateObject("Scripting.FileSystemObject")

strDir    = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
strScript = strDir & "gifty_av.py"

' ── 1. Try the installer-written path hint first ─────────────────────────
strHintFile = strDir & "python_path.txt"
strPythonW  = ""

If objFSO.FileExists(strHintFile) Then
    Dim ts : Set ts = objFSO.OpenTextFile(strHintFile, 1)
    strHint = Trim(ts.ReadAll)
    ts.Close
    If strHint <> "" And objFSO.FileExists(strHint) Then
        strPythonW = strHint
    End If
End If

' ── 2. Walk common install locations if hint didn't work ─────────────────
If strPythonW = "" Then
    Dim localAppData : localAppData = objShell.ExpandEnvironmentStrings("%LOCALAPPDATA%")
    Dim progFiles    : progFiles    = objShell.ExpandEnvironmentStrings("%PROGRAMFILES%")
    Dim progFilesX86 : progFilesX86 = objShell.ExpandEnvironmentStrings("%PROGRAMFILES(X86)%")

    Dim candidates(9)
    candidates(0) = localAppData & "\Programs\Python\Python312\pythonw.exe"
    candidates(1) = localAppData & "\Programs\Python\Python311\pythonw.exe"
    candidates(2) = localAppData & "\Programs\Python\Python310\pythonw.exe"
    candidates(3) = localAppData & "\Programs\Python\Python39\pythonw.exe"
    candidates(4) = progFiles    & "\Python312\pythonw.exe"
    candidates(5) = progFiles    & "\Python311\pythonw.exe"
    candidates(6) = progFiles    & "\Python310\pythonw.exe"
    candidates(7) = progFilesX86 & "\Python312\pythonw.exe"
    candidates(8) = progFilesX86 & "\Python311\pythonw.exe"
    candidates(9) = progFilesX86 & "\Python310\pythonw.exe"

    Dim c
    For Each c In candidates
        If objFSO.FileExists(c) Then
            strPythonW = c
            Exit For
        End If
    Next
End If

' ── 3. Fall back to PATH-based pythonw.exe ───────────────────────────────
If strPythonW = "" Then
    strPythonW = "pythonw.exe"   ' rely on PATH; may fail silently if missing
End If

' ── 4. Launch ─────────────────────────────────────────────────────────────
On Error Resume Next
objShell.Run """" & strPythonW & """ """ & strScript & """", 0, False

If Err.Number <> 0 Then
    Err.Clear
    On Error GoTo 0
    MsgBox "Gifty Antivirus could not start." & vbCrLf & vbCrLf & _
           "Python was not found on this machine." & vbCrLf & vbCrLf & _
           "Please install Python 3.12 from:" & vbCrLf & _
           "https://www.python.org/downloads/" & vbCrLf & vbCrLf & _
           "Tick 'Add Python to PATH' during install, then try again.", _
           vbCritical, "Gifty Antivirus — Python Required"
End If
