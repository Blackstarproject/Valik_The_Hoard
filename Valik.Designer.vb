<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()> _
Partial Class Valik
    Inherits System.Windows.Forms.Form

    'Form overrides dispose to clean up the component list.
    <System.Diagnostics.DebuggerNonUserCode()> _
    Protected Overrides Sub Dispose(ByVal disposing As Boolean)
        Try
            If disposing AndAlso components IsNot Nothing Then
                components.Dispose()
            End If
        Finally
            MyBase.Dispose(disposing)
        End Try
    End Sub

    'Required by the Windows Form Designer
    Private components As System.ComponentModel.IContainer

    'NOTE: The following procedure is required by the Windows Form Designer
    'It can be modified using the Windows Form Designer.  
    'Do not modify it using the code editor.
    <System.Diagnostics.DebuggerStepThrough()> _
    Private Sub InitializeComponent()
        Me.components = New System.ComponentModel.Container()
        Me.Timer1 = New System.Windows.Forms.Timer(Me.components)
        Me.Cmd_get = New System.Windows.Forms.Timer(Me.components)
        Me.Tmr_start_worm = New System.Windows.Forms.Timer(Me.components)
        Me.SuspendLayout()
        '
        'Timer1
        '
        Me.Timer1.Enabled = True
        Me.Timer1.Interval = 1000
        '
        'Cmd_get
        '
        Me.Cmd_get.Enabled = True
        Me.Cmd_get.Interval = 10000
        '
        'Tmr_start_worm
        '
        Me.Tmr_start_worm.Enabled = True
        Me.Tmr_start_worm.Interval = 15000
        '
        'Valik
        '
        Me.AutoScaleDimensions = New System.Drawing.SizeF(8.0!, 16.0!)
        Me.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font
        Me.ClientSize = New System.Drawing.Size(265, 159)
        Me.Name = "Valik"
        Me.ShowInTaskbar = False
        Me.Text = "Form1"
        Me.WindowState = System.Windows.Forms.FormWindowState.Minimized
        Me.ResumeLayout(False)

    End Sub

    Friend WithEvents Timer1 As Timer
    Friend WithEvents Cmd_get As Timer
    Friend WithEvents Tmr_start_worm As Timer
End Class
