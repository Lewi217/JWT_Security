package Wanjohi.Lewis.Security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService<userDetails> {

    private static final String SECRET_KEY = "Aa7R2w4SMBaAKRZmmhLFPHZ92rI5eXpjP4T131Lo1hiPokPY2ocfJAebpZ+ybOyEVRqeU3rxzo8fgrNTHOau04Vu7n2kcijZmkflskTRxF4=\n";


    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

   public String generateToken(
           Map<String, Object> extraClaims
           User

   )

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
