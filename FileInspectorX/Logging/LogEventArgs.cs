using System;

namespace FileInspectorX;

/// <summary>
/// EventArgs carrying diagnostic message details and optional progress metadata.
/// </summary>
public class LogEventArgs : EventArgs {
    /// <summary>Progress percentage.</summary>
    public int? ProgressPercentage { get; set; }

    /// <summary>Total steps for the progress operation (optional).</summary>
    public int? ProgressTotalSteps { get; set; }

    /// <summary>Current step of the progress operation (optional).</summary>
    public int? ProgressCurrentSteps { get; set; }

    /// <summary>Current operation label for progress.</summary>
    public string ProgressCurrentOperation { get; set; } = string.Empty;

    /// <summary>Overall activity label for progress.</summary>
    public string ProgressActivity { get; set; } = string.Empty;

    /// <summary>Message to be written including argument substitution.</summary>
    public string FullMessage { get; set; } = string.Empty;

    /// <summary>Raw message before argument substitution.</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>Arguments accompanying the formatted message.</summary>
    public object[] Args { get; set; } = Array.Empty<object>();

    /// <summary>Create a message event with formatting args.</summary>
    public LogEventArgs(string message, object[] args) {
        Message = message;
        Args = args;
        FullMessage = string.Format(message, args);
    }

    /// <summary>Create a message event without formatting args.</summary>
    public LogEventArgs(string message) {
        Message = message;
        FullMessage = message;
    }

    /// <summary>Create a progress event with optional step counters.</summary>
    public LogEventArgs(string activity, string currentOperation, int? currentSteps, int? totalSteps, int? percentage) {
        ProgressActivity = activity;
        ProgressCurrentOperation = currentOperation;
        ProgressCurrentSteps = currentSteps;
        ProgressTotalSteps = totalSteps;
        ProgressPercentage = percentage;
    }
}

