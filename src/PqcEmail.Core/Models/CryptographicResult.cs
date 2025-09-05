using System;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Represents the result of a cryptographic operation with error handling.
    /// </summary>
    /// <typeparam name="T">Type of the successful result data</typeparam>
    public class CryptographicResult<T>
    {
        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the result data if the operation was successful.
        /// </summary>
        public T? Data { get; }

        /// <summary>
        /// Gets the error message if the operation failed.
        /// </summary>
        public string? ErrorMessage { get; }

        /// <summary>
        /// Gets the exception that caused the failure, if any.
        /// </summary>
        public Exception? Exception { get; }

        private CryptographicResult(bool isSuccess, T? data, string? errorMessage, Exception? exception)
        {
            IsSuccess = isSuccess;
            Data = data;
            ErrorMessage = errorMessage;
            Exception = exception;
        }

        /// <summary>
        /// Creates a successful result with data.
        /// </summary>
        /// <param name="data">The result data</param>
        /// <returns>A successful cryptographic result</returns>
        public static CryptographicResult<T> Success(T data)
        {
            return new CryptographicResult<T>(true, data, null, null);
        }

        /// <summary>
        /// Creates a failed result with an error message.
        /// </summary>
        /// <param name="errorMessage">The error message</param>
        /// <returns>A failed cryptographic result</returns>
        public static CryptographicResult<T> Failure(string errorMessage)
        {
            return new CryptographicResult<T>(false, default(T), errorMessage, null);
        }

        /// <summary>
        /// Creates a failed result with an exception.
        /// </summary>
        /// <param name="exception">The exception that caused the failure</param>
        /// <returns>A failed cryptographic result</returns>
        public static CryptographicResult<T> Failure(Exception exception)
        {
            return new CryptographicResult<T>(false, default(T), exception.Message, exception);
        }

        /// <summary>
        /// Creates a failed result with an error message and exception.
        /// </summary>
        /// <param name="errorMessage">The error message</param>
        /// <param name="exception">The exception that caused the failure</param>
        /// <returns>A failed cryptographic result</returns>
        public static CryptographicResult<T> Failure(string errorMessage, Exception exception)
        {
            return new CryptographicResult<T>(false, default(T), errorMessage, exception);
        }
    }
}