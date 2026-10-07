using CulinaryBlog.Application.Common.Behaviors;
using FluentValidation;
using MediatR;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace CulinaryBlog.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        var assembly = typeof(DependencyInjection).Assembly;

        services.AddMediatR(configuration => configuration.RegisterServicesFromAssembly(assembly));
        services.AddValidatorsFromAssembly(assembly, includeInternalTypes: true);
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));
        services.AddMemoryCache();
        services.AddScoped<CulinaryBlog.Application.Abstractions.Identity.IRecipeAuthorizationService, CulinaryBlog.Application.Auth.Services.RecipeAuthorizationService>();

        return services;
    }
}
