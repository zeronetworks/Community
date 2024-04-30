@{
    ModuleVersion     = '1.0'
    Author            = 'Thomas Obarowski (https://www.linkedin.com/in/tjobarow/)'
    Description       = 'This module will use a PSSession to connect to the provided Segment Server. It attempts
    to compress C:\Program Files\Zero Networks\BreakGlass\ to BreakGlass.zip, and then copy
    it to the local filesystem (host running module). It then closes the previous pssession
    and enters a new one on the destination server. It copies the breakglass.zip file to 
    a remote directory provided at run time. It then closes the pssession and removes the 
    local copy of BreakGlass.zip'
    FunctionsToExport = 'Sync-BreakGlassDirectory'
    RootModule        = '.\sync_breakglass_directory.psm1'
}
