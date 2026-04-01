package io.apiguard.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Binds {@code apiguard.*} properties from {@code application.yml} / {@code application.properties}.
 *
 * <pre>
 * apiguard:
 *   jwt:
 *     public-key: classpath:keys/public.pem
 *     algorithm: RSA          # RSA (RS256) or EC (ES256)
 *     issuer: https://auth.yourcompany.com
 *     audience: api
 *   rate-limit:
 *     max-calls: 100
 *     window-seconds: 60
 *   public-paths:
 *     - /actuator/health
 *     - /swagger-ui
 *     - /v3/api-docs
 * </pre>
 */
@ConfigurationProperties(prefix = "apiguard")
public class ApiguardProperties {

    private final Jwt jwt = new Jwt();
    private final RateLimit rateLimit = new RateLimit();
    private List<String> publicPaths = List.of("/actuator/health");

    public Jwt getJwt()                  { return jwt;         }
    public RateLimit getRateLimit()      { return rateLimit;   }
    public List<String> getPublicPaths() { return publicPaths; }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    public static class Jwt {
        private String publicKey;
        private String algorithm = "RSA";
        private String issuer;
        private String audience;

        public String getPublicKey()  { return publicKey;  }
        public String getAlgorithm()  { return algorithm;  }
        public String getIssuer()     { return issuer;     }
        public String getAudience()   { return audience;   }

        public void setPublicKey(String publicKey)  { this.publicKey  = publicKey;  }
        public void setAlgorithm(String algorithm)  { this.algorithm  = algorithm;  }
        public void setIssuer(String issuer)         { this.issuer     = issuer;     }
        public void setAudience(String audience)     { this.audience   = audience;   }
    }

    public static class RateLimit {
        private int maxCalls      = 100;
        private int windowSeconds = 60;

        public int getMaxCalls()      { return maxCalls;      }
        public int getWindowSeconds() { return windowSeconds; }

        public void setMaxCalls(int maxCalls)            { this.maxCalls      = maxCalls;      }
        public void setWindowSeconds(int windowSeconds)  { this.windowSeconds = windowSeconds; }
    }
}
