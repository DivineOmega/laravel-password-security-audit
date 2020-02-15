# Laravel Password Security Audit

This package provides an Artisan command to audit the security of your user's passwords.

Laravel Password Security Audit works by executing a long running process that checks your users passwords against
a list of over 10k commonly used weak passwords. When complete, it outputs a report of 
those users that are affected and the passwords that were found. 

## Installation

To install Laravel Password Security Audit, just run the following command from the
root of your project.

```bash
composer require divineomega/laravel-password-security-audit
```

## Usage

In a standard Laravel installation using the default `\App\User` model, you can just 
run the `security:password-audit` Artisan command.

```bash
php artisan security:password-audit
```

While running a progress bar will be displayed indicating which user is being checked,
and an estimate of how long the process will take to complete. 

The speed of this process will take is dependent on the number of users your project 
has and your server's CPU performance. Multiple CPU cores will be taken advantage of 
if available.   

```
User 1   3.6%   33/560168   ETC: 4h 39m   Elapsed: 6s   ▓░░░░░░░░░░░░░░░░░░░  
```

When complete, you will be presented with a table of users with weak passwords.
This will include the user's primary key (usually the `id` field), the password
found and its associated hash. 

### Custom user model

If you've moved the `User` model, or want to check a different model, you can use
the `--user-model` option. See the following example.

```bash
php artisan security:password-audit --user-model=\\App\\Models\\User
```

### Custom password field

If the passwords you wish to check are stored in a different field, you can change
this using the `--password-field` option. See the example below.

```bash
php artisan security:password-audit --password-field=new_password
```