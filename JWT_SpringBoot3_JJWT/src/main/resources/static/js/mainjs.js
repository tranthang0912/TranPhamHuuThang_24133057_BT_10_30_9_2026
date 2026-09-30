(function () {
    'use strict';

    var emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    function byId(id) {
        return document.getElementById(id);
    }

    function showMessage(id, message, type) {
        var element = byId(id);
        if (!element) {
            return;
        }
        element.className = 'message message-' + type;
        element.textContent = message;
        element.hidden = false;
    }

    function hideMessage(id) {
        var element = byId(id);
        if (element) {
            element.hidden = true;
            element.textContent = '';
        }
    }

    function clearErrors(form) {
        form.querySelectorAll('.field-error').forEach(function (element) {
            element.textContent = '';
        });
        form.querySelectorAll('.input-shell').forEach(function (element) {
            element.classList.remove('has-error');
        });
    }

    function setFieldError(inputId, errorId, message) {
        var input = byId(inputId);
        var error = byId(errorId);
        if (input) {
            input.closest('.input-shell').classList.add('has-error');
        }
        if (error) {
            error.textContent = message;
        }
    }

    function setLoading(buttonId, loading, loadingText, normalText) {
        var button = byId(buttonId);
        if (!button) {
            return;
        }
        button.disabled = loading;
        button.classList.toggle('is-loading', loading);
        button.querySelector('.button-label').textContent = loading ? loadingText : normalText;
    }

    async function readError(response, fallback) {
        try {
            var body = await response.json();
            return body.description || body.detail || body.message || fallback;
        } catch (error) {
            return fallback;
        }
    }

    function initializePasswordToggles() {
        document.querySelectorAll('[data-password-toggle]').forEach(function (button) {
            button.addEventListener('click', function () {
                var input = byId(button.dataset.passwordToggle);
                var showing = input.type === 'text';
                input.type = showing ? 'password' : 'text';
                button.textContent = showing ? 'Hiện' : 'Ẩn';
                button.setAttribute('aria-pressed', String(!showing));
                button.setAttribute('aria-label', showing ? 'Hiện mật khẩu' : 'Ẩn mật khẩu');
            });
        });
    }

    function initializeLoginPage() {
        var form = byId('loginForm');
        if (!form) {
            return;
        }

        var query = new URLSearchParams(window.location.search);
        var emailFromRegistration = query.get('email');
        if (emailFromRegistration) {
            byId('email').value = emailFromRegistration;
        }

        if (query.get('reason') === 'registered') {
            showMessage('loginMessage', 'Đăng ký thành công. Hãy đăng nhập bằng tài khoản vừa tạo.', 'success');
        } else if (query.get('reason') === 'required') {
            showMessage('loginMessage', 'Vui lòng đăng nhập để xem hồ sơ.', 'info');
        } else if (query.get('reason') === 'logout') {
            showMessage('loginMessage', 'Bạn đã đăng xuất an toàn.', 'success');
        } else if (localStorage.getItem('token')) {
            showMessage('loginMessage', 'Bạn đã có phiên đăng nhập. Đăng nhập lại để làm mới phiên.', 'info');
        }

        form.addEventListener('submit', async function (event) {
            event.preventDefault();
            clearErrors(form);
            hideMessage('loginMessage');

            var email = byId('email').value.trim();
            var password = byId('password').value;
            var valid = true;

            if (!emailPattern.test(email)) {
                setFieldError('email', 'emailError', 'Vui lòng nhập một địa chỉ email hợp lệ.');
                valid = false;
            }
            if (password.length < 6) {
                setFieldError('password', 'passwordError', 'Mật khẩu phải có ít nhất 6 ký tự.');
                valid = false;
            }
            if (!valid) {
                return;
            }

            setLoading('loginButton', true, 'Đang xác thực...', 'Đăng nhập');
            try {
                var response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email: email, password: password})
                });
                if (!response.ok) {
                    throw new Error(await readError(response, 'Email hoặc mật khẩu không chính xác.'));
                }

                var data = await response.json();
                localStorage.setItem('token', data.token);
                showMessage('loginMessage', 'Đăng nhập thành công. Đang chuyển hướng...', 'success');
                window.setTimeout(function () {
                    window.location.href = '/user/profile';
                }, 450);
            } catch (error) {
                showMessage('loginMessage', error.message || 'Không thể kết nối tới máy chủ.', 'error');
                setLoading('loginButton', false, 'Đang xác thực...', 'Đăng nhập');
            }
        });
    }

    function initializeRegisterPage() {
        var form = byId('registerForm');
        if (!form) {
            return;
        }

        form.addEventListener('submit', async function (event) {
            event.preventDefault();
            clearErrors(form);
            hideMessage('registerMessage');

            var fullName = byId('fullName').value.trim().replace(/\s+/g, ' ');
            var email = byId('registerEmail').value.trim().toLowerCase();
            var password = byId('registerPassword').value;
            var confirmPassword = byId('confirmPassword').value;
            var valid = true;

            if (fullName.length < 2 || fullName.length > 50) {
                setFieldError('fullName', 'fullNameError', 'Họ và tên phải có từ 2 đến 50 ký tự.');
                valid = false;
            }
            if (!emailPattern.test(email) || email.length > 100) {
                setFieldError('registerEmail', 'registerEmailError', 'Vui lòng nhập một địa chỉ email hợp lệ.');
                valid = false;
            }
            if (password.length < 6) {
                setFieldError('registerPassword', 'registerPasswordError', 'Mật khẩu phải có ít nhất 6 ký tự.');
                valid = false;
            }
            if (confirmPassword !== password) {
                setFieldError('confirmPassword', 'confirmPasswordError', 'Mật khẩu xác nhận chưa khớp.');
                valid = false;
            }
            if (!valid) {
                return;
            }

            setLoading('registerButton', true, 'Đang tạo tài khoản...', 'Tạo tài khoản');
            try {
                var response = await fetch('/auth/signup', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        fullName: fullName,
                        email: email,
                        password: password
                    })
                });
                if (!response.ok) {
                    throw new Error(await readError(response, 'Không thể tạo tài khoản.'));
                }

                showMessage('registerMessage', 'Tạo tài khoản thành công. Đang chuyển tới đăng nhập...', 'success');
                window.setTimeout(function () {
                    window.location.href = '/login?reason=registered&email=' + encodeURIComponent(email);
                }, 650);
            } catch (error) {
                showMessage('registerMessage', error.message || 'Không thể kết nối tới máy chủ.', 'error');
                setLoading('registerButton', false, 'Đang tạo tài khoản...', 'Tạo tài khoản');
            }
        });
    }

    function getInitials(name) {
        if (!name) {
            return 'HT';
        }
        return name.trim().split(/\s+/).slice(-2).map(function (part) {
            return part.charAt(0).toUpperCase();
        }).join('');
    }

    function formatDate(value) {
        if (!value) {
            return 'Chưa cập nhật';
        }
        var date = new Date(value);
        return Number.isNaN(date.getTime())
            ? 'Chưa cập nhật'
            : new Intl.DateTimeFormat('vi-VN', {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric'
            }).format(date);
    }

    function renderProfile(data) {
        var fullName = data.fullName || 'Người dùng';
        byId('profileName').textContent = fullName;
        byId('profileEmail').textContent = data.email || 'Chưa cập nhật email';
        byId('createdAt').textContent = formatDate(data.createdAt);
        byId('avatarFallback').textContent = getInitials(fullName);

        if (data.images && String(data.images).trim()) {
            byId('images').src = data.images;
            byId('images').hidden = false;
            byId('avatarFallback').hidden = true;
        }
        byId('profileContent').classList.remove('loading');
    }

    function initializeProfilePage() {
        if (!byId('profilePage')) {
            return;
        }

        byId('currentDate').textContent = new Intl.DateTimeFormat('vi-VN', {
            weekday: 'long',
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        }).format(new Date());

        var token = localStorage.getItem('token');
        if (!token) {
            window.location.replace('/login?reason=required');
            return;
        }

        byId('images').addEventListener('error', function () {
            byId('images').hidden = true;
            byId('avatarFallback').hidden = false;
        });

        fetch('/users/me', {
            headers: {'Authorization': 'Bearer ' + token}
        }).then(async function (response) {
            if (!response.ok) {
                throw new Error(await readError(response, 'Phiên đăng nhập đã hết hạn.'));
            }
            return response.json();
        }).then(renderProfile).catch(function (error) {
            localStorage.removeItem('token');
            showMessage('profileMessage', error.message + ' Vui lòng đăng nhập lại.', 'error');
            window.setTimeout(function () {
                window.location.replace('/login?reason=required');
            }, 1200);
        });

        byId('logout').addEventListener('click', function () {
            localStorage.removeItem('token');
            window.location.href = '/login?reason=logout';
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        initializePasswordToggles();
        initializeLoginPage();
        initializeRegisterPage();
        initializeProfilePage();
    });
})();

