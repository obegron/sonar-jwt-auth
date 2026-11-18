package io.github.obegron.sonarjwt;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * This extension calls SonarQube internals. Before registering anything, check that every class and method it uses exists with the
 * expected signature, so an incompatible SonarQube makes the feature switch itself off with a clear error instead of breaking startup.
 */
final class Compat {
  private Compat() { }

  static List<String> problems(ClassLoader cl) {
    List<String> p = new ArrayList<>();
    check(p, cl, "org.sonar.server.authentication.ServiceAuthentication", "authenticate", "org.sonar.api.server.http.HttpRequest");
    check(p, cl, "org.sonar.db.DbClient", "openSession", "boolean");
    check(p, cl, "org.sonar.db.DbClient", "userDao");
    check(p, cl, "org.sonar.db.user.UserDao", "selectActiveUserByLogin", "org.sonar.db.DbSession", "java.lang.String");
    check(p, cl, "org.sonar.db.user.UserDao", "selectByExternalIdAndIdentityProvider", "org.sonar.db.DbSession", "java.lang.String", "java.lang.String");
    check(p, cl, "org.sonar.db.user.UserDto", "getExternalIdentityProvider");
    check(p, cl, "org.sonar.db.user.UserDto", "isActive");
    check(p, cl, "org.sonar.db.user.UserDto", "getLogin");
    check(p, cl, "org.sonar.server.user.UserSessionFactory", "create", "org.sonar.db.user.UserDto", "boolean");
    check(p, cl, "org.sonar.server.authentication.UserRegistrar", "register", "org.sonar.server.authentication.UserRegistration");
    check(p, cl, "org.sonar.server.authentication.UserRegistration", "builder");
    check(p, cl, "org.sonar.server.authentication.event.AuthenticationEvent$Source", "external", "org.sonar.api.server.authentication.IdentityProvider");
    return p;
  }

  /** @param method null = check for a constructor with these parameters */
  private static void check(List<String> problems, ClassLoader cl, String cls, String method, String... params) {
    try {
      Class<?>[] types = new Class<?>[params.length];
      for (int i = 0; i < params.length; i++) types[i] = params[i].equals("boolean") ? boolean.class : Class.forName(params[i], false, cl);
      Class<?> c = Class.forName(cls, false, cl);
      if (method == null) c.getConstructor(types);
      else { Method m = c.getMethod(method, types); if (m == null) throw new NoSuchMethodException(); }
    } catch (ReflectiveOperationException | LinkageError e) {
      problems.add(cls + (method == null ? "(constructor)" : "#" + method) + " -> " + e.getClass().getSimpleName() + " " + e.getMessage());
    }
  }
}
