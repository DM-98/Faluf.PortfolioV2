using System.Linq.Expressions;
using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Faluf.Portfolio.Infrastructure.Helpers;

public static class EFCoreHelper
{
    public static void AddSoftDeleteQueryFilter(this IMutableEntityType mutableEntityType)
    {
        ParameterExpression parameter = Expression.Parameter(mutableEntityType.ClrType, "e");
        MethodInfo propertyMethodInfo = typeof(EF).GetMethod("Property")?.MakeGenericMethod(typeof(DateTime?))!;
        MethodCallExpression deletedAtProperty = Expression.Call(propertyMethodInfo, parameter, Expression.Constant("DeletedAt"));
        BinaryExpression compareExpression = Expression.MakeBinary(ExpressionType.Equal, deletedAtProperty, Expression.Constant(null, typeof(DateTime?)));
        LambdaExpression lambda = Expression.Lambda(compareExpression, parameter);

        mutableEntityType.SetQueryFilter(lambda);
    }
}