<?php

namespace DivineOmega\LaravelPasswordSecurityAudit\Console\Commands;

use DivineOmega\CliProgressBar\ProgressBar;
use DivineOmega\LaravelPasswordSecurityAudit\Objects\CrackedUser;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Spatie\Async\Pool;

class PasswordAudit extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:password-audit {--user-model=\\App\\User} {--password-field=password}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Audits the security of your user\'s passwords';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $passwords = file(__DIR__ . '/../../../resources/password-list.txt', FILE_IGNORE_NEW_LINES);

        $userModelClass = $this->option('user-model');
        $passwordField = $this->option('password-field');

        if (!class_exists($userModelClass)) {
            $this->error('Specified user model is not a valid class.');
            exit;
        }

        $userModel = new $userModelClass();

        if (!$userModel instanceof Model) {
            $this->error('Specified user model is not a Eloquent model.');
            exit;
        }

        $query = $userModel->query()
            ->select([$userModel->getKeyName(), 'password']);

        $numUsers = $query->count();

        if ($numUsers <= 0) {
            $this->error('No users found.');
            exit;
        }

        $numPasswords = count($passwords);

        $crackedUsers = collect();

        $progressBar = new ProgressBar();
        $progressBar->setMaxProgress($numUsers * count($passwords));
        $progressBar->display();

        $userIndex = 0;

        $query->chunk(1000, function ($users) use ($passwords, $crackedUsers, $progressBar, $userIndex, $numPasswords, $passwordField) {
            /** @var Model $user */
            foreach ($users as $user) {
                $progressBar
                    ->setMessage("User ".$user->getKey())
                    ->setProgress($userIndex * $numPasswords)
                    ->display();

                $userIndex++;
                $hash = $user->$passwordField;

                $pool = Pool::create();
                $pool->concurrency(20);

                foreach($passwords as $password) {
                    $pool->add(function () use ($password, $hash) {
                        return password_verify($password, $hash);
                    })->then(function($passwordFound) use ($crackedUsers, $user, $password, $hash, $progressBar, $pool) {
                        if ($passwordFound) {
                            $crackedUsers->push(
                                new CrackedUser($user->getKey(), $password, $hash)
                            );
                            $pool->stop();
                        }
                        $progressBar->advance()->display();
                    });
                }

                $pool->wait();

            }

        });

        $progressBar->complete();

        $crackedUsersCount = $crackedUsers->count();

        $this->line($crackedUsersCount.' user password(s) were found to be weak.');

        if ($crackedUsersCount > 0) {
            $this->table([
                'Key ('.$userModel->getKeyName().')',
                'Password',
                'Hash'
            ], $crackedUsers->toArray());
        }

    }
}