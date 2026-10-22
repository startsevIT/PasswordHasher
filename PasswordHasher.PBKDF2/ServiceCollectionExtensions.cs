using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PasswordHasher.Abstractions;

namespace PasswordHasher.PBKDF2;

/// <summary>DI extensions for registering the PBKDF2 password hasher.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the password hasher using configuration from the <c>PasswordHasher</c> section.
    /// </summary>
    public static IServiceCollection AddPasswordHasher(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return services.AddPasswordHasher(configuration.GetSection(PasswordHasherOptions.SectionName));
    }

    /// <summary>
    /// Registers the password hasher using configuration from the specified section.
    /// </summary>
    public static IServiceCollection AddPasswordHasher(
        this IServiceCollection services,
        IConfigurationSection section)
    {
        ArgumentNullException.ThrowIfNull(section);

        services
            .AddOptions<PasswordHasherOptions>()
            .Bind(section)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        RegisterCore(services);
        return services;
    }

    /// <summary>
    /// Registers the password hasher using programmatic configuration.
    /// </summary>
    public static IServiceCollection AddPasswordHasher(
        this IServiceCollection services,
        Action<PasswordHasherOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        services
            .AddOptions<PasswordHasherOptions>()
            .Configure(configure)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        RegisterCore(services);
        return services;
    }

    private static void RegisterCore(IServiceCollection services)
    {
        // One instance serves all interfaces so that _dummyHash is computed once.
        services.TryAddSingleton<PasswordHasher>();
        services.TryAddSingleton<IPasswordHasher>(sp => sp.GetRequiredService<PasswordHasher>());
        services.TryAddSingleton<IMigratingPasswordHasher>(sp => sp.GetRequiredService<PasswordHasher>());
    }
}