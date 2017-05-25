/*
 * Copyright 2000-2017 JetBrains s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.jetbrains.python.debugger;


import com.intellij.execution.ExecutionException;
import com.intellij.execution.RunManager;
import com.intellij.execution.RunnerAndConfigurationSettings;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.configurations.RunConfiguration;
import com.intellij.execution.process.*;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.util.Key;
import com.intellij.openapi.util.io.FileUtil;
import com.intellij.openapi.util.text.StringUtil;
import com.intellij.util.ui.UIUtil;
import com.jetbrains.python.run.PythonRunConfiguration;
import com.jetbrains.python.sdk.PythonEnvUtil;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GenerateRevDBLogAction extends AnAction {
  private static final String REVDB_PATH = "/usr/local/lib/pypy/pypy/goal/pypy-revdb";
  private static final String ERROR_TITLE = "Error While Generating RevDB Log";
  private Project myProject;

  @Override
  public void actionPerformed(AnActionEvent event) {
      try {
        myProject = event.getProject();
        final RunManager runManager = RunManager.getInstance(myProject);
        final RunnerAndConfigurationSettings selectedConfiguration = runManager.getSelectedConfiguration();
        if (selectedConfiguration == null) {
          throw new ExecutionException("Python Run Configuration should be selected");
        }
        final RunConfiguration configuration = selectedConfiguration.getConfiguration();
        if (!(configuration instanceof PythonRunConfiguration)) {
          throw new ExecutionException("Python Run Configuration should be selected");
        }
        PythonRunConfiguration runConfiguration = (PythonRunConfiguration)configuration;
        final String sdkPath = runConfiguration.getSdkHome();

        final List<String> cmdline = new ArrayList<>();
        cmdline.add(FileUtil.toSystemDependentName(REVDB_PATH));
        cmdline.add(runConfiguration.getScriptName());

        final String logFilePath = runConfiguration.getScriptName().replace(".py", "_log.rdb");
        final Map<String, String> environment = new HashMap<>(System.getenv());
        environment.put("REVDB",
                        FileUtil.toSystemDependentName(logFilePath));
        PythonEnvUtil.setPythonUnbuffered(environment);
        PythonEnvUtil.setPythonDontWriteBytecode(environment);
        if (sdkPath != null) {
          PythonEnvUtil.resetHomePathChanges(sdkPath, environment);
        }

        GeneralCommandLine commandLine = new GeneralCommandLine(cmdline).withEnvironment(environment);
        Process process = commandLine.createProcess();
        ProgressManager.getInstance().run(new Task.Backgroundable(myProject, "Generate RevDB Log") {
          @Override
          public void run(@NotNull ProgressIndicator indicator) {
            final CapturingProcessHandler handler =
              new CapturingProcessHandler(process, commandLine.getCharset(), commandLine.getCommandLineString());
            handler.addProcessListener(new ProcessAdapter() {
              @Override
              public void onTextAvailable(ProcessEvent event, Key outputType) {
                if (outputType == ProcessOutputTypes.STDOUT || outputType == ProcessOutputTypes.STDERR) {
                  for (String line : StringUtil.splitByLines(event.getText())) {
                    if (isSignificantOutput(line)) {
                      indicator.setText2(line.trim());
                    }
                  }
                }
              }

              private boolean isSignificantOutput(String line) {
                return line.trim().length() > 3;
              }
            });
            final ProcessOutput result = handler.runProcessWithProgressIndicator(indicator);
            final int exitCode = result.getExitCode();
            if (exitCode != 0) {
              final String message = StringUtil.isEmptyOrSpaces(result.getStdout()) && StringUtil.isEmptyOrSpaces(result.getStderr())
                                     ? "Permission denied"
                                     : "Non-zero exit code (" + exitCode + "): \n" + result.getStderr();
              UIUtil.invokeLaterIfNeeded(() -> showErrorDialog(message));
            }
          }
        });

      }
      catch (ExecutionException e) {
        showErrorDialog(e.getMessage());
      }
    }

  private void showErrorDialog(String message) {
    Messages.showMessageDialog(myProject, message, ERROR_TITLE, null);
  }
}

