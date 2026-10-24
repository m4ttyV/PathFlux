namespace PathFlux.Application;

/// <summary>A fixed, safe message from the engine boundary, suitable for the UI and local log.</summary>
public sealed class EngineOperationException(string message) : Exception(message);
