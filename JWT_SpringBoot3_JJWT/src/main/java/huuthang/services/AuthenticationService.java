package huuthang.services;

import huuthang.entity.User;
import huuthang.exceptions.DuplicateEmailException;
import huuthang.models.LoginUserModel;
import huuthang.models.RegisterUserModel;
import huuthang.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User signup(RegisterUserModel input) {
        String fullName = input.getFullName() == null ? "" : input.getFullName().trim();
        String email = input.getEmail() == null ? "" : input.getEmail().trim().toLowerCase(Locale.ROOT);
        String password = input.getPassword() == null ? "" : input.getPassword();

        if (fullName.length() < 2 || fullName.length() > 50) {
            throw new IllegalArgumentException("Họ và tên phải có từ 2 đến 50 ký tự.");
        }
        if (!email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$") || email.length() > 100) {
            throw new IllegalArgumentException("Địa chỉ email không hợp lệ.");
        }
        if (password.length() < 6) {
            throw new IllegalArgumentException("Mật khẩu phải có ít nhất 6 ký tự.");
        }
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new DuplicateEmailException("Email này đã được sử dụng.");
        }

        User user = new User();
        user.setFullName(fullName);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setImages("");
        return userRepository.save(user);
    }

    public User authenticate(LoginUserModel input) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                )
        );

        return userRepository.findByEmail(input.getEmail())
                .orElseThrow();
    }
}
